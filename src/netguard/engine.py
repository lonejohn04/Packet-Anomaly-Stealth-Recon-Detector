"""Core NetGuard packet analysis orchestrator for PCAP files and live interfaces."""

from __future__ import annotations

import math
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff
from scapy.utils import PcapReader

from .config import DetectorConfig, QuarantineConfig
from .detectors import ArpSpoofDetector, DnsTunnelDetector, PortScanDetector
from .detectors.base import format_utc_timestamp
from .models import Alert, AnalysisResult
from .quarantine import NftablesQuarantineManager

AlertCallback = Callable[[Alert], None]


class PcapReadError(Exception):
    """Raised when a capture file is missing, empty, or corrupted."""


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_packet_timestamp(pkt: Any) -> float:
    """Extract packet capture timestamp as finite float, falling back to wall clock."""
    raw = getattr(pkt, "time", None)
    if raw is not None:
        try:
            val = float(raw)
            if math.isfinite(val) and val >= 0.0:
                return val
        except (TypeError, ValueError):
            pass
    return time.time()


def _classify_protocol(pkt: Any) -> str:
    """Assign each packet to a primary protocol bucket for telemetry breakdown."""
    if DNS in pkt:
        return "DNS"
    if ARP in pkt:
        return "ARP"
    if ICMP in pkt:
        return "ICMP"
    # Check ICMPv6 layers cleanly without importing every ICMPv6 subclass
    for layer in pkt.layers():
        if layer.__name__.startswith("ICMPv6"):
            return "ICMP"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if IPv6 in pkt:
        return "IPv6"
    return "Other"


class PacketAnalyzer:
    """Coordinates stateful detectors, telemetry aggregation, and nftables quarantine."""

    def __init__(
        self,
        detector_config: DetectorConfig | None = None,
        quarantine_config: QuarantineConfig | None = None,
    ) -> None:
        self.detector_config = detector_config or DetectorConfig()
        self.quarantine_config = quarantine_config or QuarantineConfig()

        self.port_scan_detector = PortScanDetector(self.detector_config)
        self.dns_tunnel_detector = DnsTunnelDetector(self.detector_config)
        self.arp_spoof_detector = ArpSpoofDetector(self.detector_config)
        self.detectors = [
            self.port_scan_detector,
            self.dns_tunnel_detector,
            self.arp_spoof_detector,
        ]
        self.quarantine_manager = NftablesQuarantineManager(self.quarantine_config)

        self.total_packets: int = 0
        self.protocol_counts: dict[str, int] = {
            "TCP": 0,
            "UDP": 0,
            "DNS": 0,
            "ARP": 0,
            "ICMP": 0,
            "IPv6": 0,
            "Other": 0,
        }
        self.alerts: list[Alert] = []
        self._packet_sec_counts: dict[int, int] = defaultdict(int)
        self._alert_sec_counts: dict[int, int] = defaultdict(int)
        self._first_pkt_ts: float | None = None
        self._last_pkt_ts: float | None = None

    def reset(self) -> None:
        """Clear all detector state, telemetry counters, and quarantine history."""
        for detector in self.detectors:
            detector.reset()
        self.quarantine_manager.reset()
        self.total_packets = 0
        for key in self.protocol_counts:
            self.protocol_counts[key] = 0
        self.alerts.clear()
        self._packet_sec_counts.clear()
        self._alert_sec_counts.clear()
        self._first_pkt_ts = None
        self._last_pkt_ts = None

    def process_packet(
        self, pkt: Any, on_alert: AlertCallback | None = None
    ) -> list[Alert]:
        """Process a single Scapy packet through all detectors and quarantine policy."""
        pkt_ts = _safe_packet_timestamp(pkt)
        self.total_packets += 1
        if self._first_pkt_ts is None or pkt_ts < self._first_pkt_ts:
            self._first_pkt_ts = pkt_ts
        if self._last_pkt_ts is None or pkt_ts > self._last_pkt_ts:
            self._last_pkt_ts = pkt_ts

        proto = _classify_protocol(pkt)
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        self._packet_sec_counts[int(pkt_ts)] += 1

        emitted: list[Alert] = []
        for detector in self.detectors:
            try:
                found = detector.process_packet(pkt, pkt_ts)
            except (Scapy_Exception, AttributeError, IndexError, KeyError, struct.error, TypeError, ValueError):
                # Malformed packet payload in one layer should never crash capture analysis
                continue
            for alert in found:
                self.quarantine_manager.evaluate_alert(alert)
                self.alerts.append(alert)
                self._alert_sec_counts[int(alert.packet_timestamp)] += 1
                emitted.append(alert)
                if on_alert is not None:
                    on_alert(alert)

        return emitted

    def _build_timeline(self, max_buckets: int = 40) -> list[dict[str, Any]]:
        """Aggregate per-second packet and alert telemetry into chart-ready buckets."""
        if not self._packet_sec_counts or self._first_pkt_ts is None or self._last_pkt_ts is None:
            return []

        start_sec = int(self._first_pkt_ts)
        end_sec = int(self._last_pkt_ts)
        span = max(1, (end_sec - start_sec) + 1)

        if span <= max_buckets:
            buckets = []
            for sec in range(start_sec, end_sec + 1):
                offset = sec - start_sec
                buckets.append({
                    "label": f"+{offset}s",
                    "timestamp": format_utc_timestamp(float(sec)),
                    "packets": self._packet_sec_counts.get(sec, 0),
                    "alerts": self._alert_sec_counts.get(sec, 0),
                })
            return buckets

        bucket_width = math.ceil(span / max_buckets)
        grouped_pkts: dict[int, int] = defaultdict(int)
        grouped_alerts: dict[int, int] = defaultdict(int)
        for sec, count in self._packet_sec_counts.items():
            idx = (sec - start_sec) // bucket_width
            grouped_pkts[idx] += count
        for sec, count in self._alert_sec_counts.items():
            idx = (sec - start_sec) // bucket_width
            grouped_alerts[idx] += count

        max_idx = (end_sec - start_sec) // bucket_width
        buckets = []
        for idx in range(max_idx + 1):
            offset = idx * bucket_width
            buckets.append({
                "label": f"+{offset}s",
                "timestamp": format_utc_timestamp(float(start_sec + offset)),
                "packets": grouped_pkts.get(idx, 0),
                "alerts": grouped_alerts.get(idx, 0),
            })
        return buckets

    def _build_result(
        self, source: str, started_at: str, started_perf: float
    ) -> AnalysisResult:
        duration_ms = (time.perf_counter() - started_perf) * 1000.0
        return AnalysisResult(
            source=source,
            started_at=started_at,
            finished_at=_utc_now_iso(),
            duration_ms=duration_ms,
            total_packets=self.total_packets,
            protocol_counts=dict(self.protocol_counts),
            alerts=list(self.alerts),
            arp_table=self.arp_spoof_detector.get_bindings(),
            dns_observations=list(self.dns_tunnel_detector.observations),
            top_targeted_ports=self.port_scan_detector.get_top_targeted_ports(),
            timeline_buckets=self._build_timeline(),
            quarantine_records=self.quarantine_manager.records,
            config={
                "detector": self.detector_config.to_dict(),
                "quarantine": self.quarantine_config.to_dict(),
            },
        )

    def analyze_packets(
        self,
        packets: Iterable[Any],
        source: str = "memory",
        on_alert: AlertCallback | None = None,
    ) -> AnalysisResult:
        """Analyze an in-memory sequence or generator of Scapy packets."""
        self.reset()
        started_at = _utc_now_iso()
        started_perf = time.perf_counter()
        for pkt in packets:
            self.process_packet(pkt, on_alert=on_alert)
        return self._build_result(source=source, started_at=started_at, started_perf=started_perf)

    def analyze_pcap(
        self,
        pcap_path: str | Path,
        on_alert: AlertCallback | None = None,
    ) -> AnalysisResult:
        """Stream-read a .pcap or .pcapng capture file and return an AnalysisResult."""
        path = Path(pcap_path)
        if not path.exists() or not path.is_file():
            raise PcapReadError(f"Capture file not found: {path}")
        if path.stat().st_size == 0:
            raise PcapReadError(f"Capture file is empty (0 bytes): {path}")

        self.reset()
        started_at = _utc_now_iso()
        started_perf = time.perf_counter()

        try:
            with PcapReader(str(path)) as reader:
                for pkt in reader:
                    self.process_packet(pkt, on_alert=on_alert)
        except (Scapy_Exception, EOFError, OSError, struct.error, ValueError) as exc:
            raise PcapReadError(f"Failed to read capture file '{path}': {exc}") from exc

        return self._build_result(source=str(path), started_at=started_at, started_perf=started_perf)

    def sniff_live(
        self,
        interface: str,
        bpf_filter: str | None = None,
        packet_count: int = 0,
        timeout: float | None = None,
        on_alert: AlertCallback | None = None,
        stop_event: threading.Event | None = None,
    ) -> AnalysisResult:
        """Capture and analyze live network packets on an interface."""
        self.reset()
        started_at = _utc_now_iso()
        started_perf = time.perf_counter()

        stop_filter = (lambda _: stop_event.is_set()) if stop_event is not None else None
        try:
            sniff(
                iface=interface,
                filter=bpf_filter or None,
                prn=lambda pkt: self.process_packet(pkt, on_alert=on_alert),
                store=False,
                count=packet_count,
                timeout=timeout,
                stop_filter=stop_filter,
            )
        except PermissionError as exc:
            raise PermissionError(
                f"Insufficient privileges to sniff on '{interface}'. "
                "Run with sudo / CAP_NET_RAW or analyze a .pcap file offline."
            ) from exc
        except (Scapy_Exception, OSError) as exc:
            raise RuntimeError(f"Live capture failed on interface '{interface}': {exc}") from exc

        return self._build_result(
            source=f"live:{interface}", started_at=started_at, started_perf=started_perf
        )
