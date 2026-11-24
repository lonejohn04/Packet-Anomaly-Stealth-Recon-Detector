"""Stateful sliding-window TCP SYN & stealth port scan detector."""

from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from typing import Any

from scapy.layers.inet import TCP

from ..config import DetectorConfig
from ..models import Alert, MitreMapping
from .base import BaseDetector, extract_ip_pair, extract_mac_pair, format_utc_timestamp

_MITRE_PORT_SCAN = MitreMapping(
    tactic="Discovery",
    technique_id="T1046",
    technique_name="Network Service Discovery",
)

# Standard 6-bit TCP control flags mask (ignores ECN ECE=0x40 and CWR=0x80)
_CORE_FLAG_MASK = 0x3F
_FIN = 0x01
_SYN = 0x02
_ACK = 0x10
_XMAS = 0x29  # FIN (0x01) | PSH (0x08) | URG (0x20)


class PortScanDetector(BaseDetector):
    """Detects TCP half-open SYN scans and stealth FIN/NULL/Xmas scans."""

    name = "port_scan"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__()
        self.config = config or DetectorConfig()
        # (scan_type, src_ip, dst_ip) -> list of (pkt_ts, dport, sport) sorted by pkt_ts
        self._windows: dict[tuple[str, str, str], list[tuple[float, int, int]]] = defaultdict(list)
        # (scan_type, src_ip, dst_ip) -> highest timestamp observed for key
        self._high_water_ts: dict[tuple[str, str, str], float] = {}
        # (src_ip, sport, dst_ip, dport) -> completion timestamp
        self._completed_flows: dict[tuple[str, int, str, int], float] = {}
        # (alert_type, src_ip, dst_ip) -> last alert packet timestamp
        self._last_alert_ts: dict[tuple[str, str, str], float] = {}
        # Destination port hit counts across scan probes
        self.port_hits: Counter[int] = Counter()

    def reset(self) -> None:
        self._alert_seq = 0
        self._windows.clear()
        self._high_water_ts.clear()
        self._completed_flows.clear()
        self._last_alert_ts.clear()
        self.port_hits.clear()

    def _prune_completed_flows(self, cutoff_ts: float) -> None:
        """Keep completed handshake cache bounded to active sliding window."""
        if len(self._completed_flows) <= 2048:
            return
        stale = [k for k, ts in self._completed_flows.items() if ts < cutoff_ts]
        for k in stale:
            del self._completed_flows[k]

    def _record_handshake_ack(
        self, src_ip: str, sport: int, dst_ip: str, dport: int, pkt_ts: float
    ) -> None:
        """Remove completed client handshakes from active half-open SYN tracking."""
        flow_key = (src_ip, sport, dst_ip, dport)
        self._completed_flows[flow_key] = pkt_ts
        syn_key = ("SYN", src_ip, dst_ip)
        win = self._windows.get(syn_key)
        if win:
            self._windows[syn_key] = [
                entry for entry in win if not (entry[1] == dport and entry[2] == sport)
            ]
        self._prune_completed_flows(pkt_ts - self.config.scan_window_seconds)

    def _classify_probe(self, core_flags: int) -> tuple[str, str, int, str] | None:
        """Classify 6-bit masked TCP flags into scan type, alert type, severity, threshold."""
        if core_flags == _SYN:
            return ("SYN", "TCP_SYN_SCAN", "HIGH", self.config.syn_scan_port_threshold)
        if core_flags == _FIN:
            return ("FIN", "TCP_FIN_SCAN", "CRITICAL", self.config.stealth_scan_port_threshold)
        if core_flags == 0x00:
            return ("NULL", "TCP_NULL_SCAN", "CRITICAL", self.config.stealth_scan_port_threshold)
        if core_flags == _XMAS:
            return ("XMAS", "TCP_XMAS_SCAN", "CRITICAL", self.config.stealth_scan_port_threshold)
        return None

    def process_packet(self, pkt: Any, pkt_ts: float) -> list[Alert]:
        if TCP not in pkt:
            return []

        src_ip, dst_ip = extract_ip_pair(pkt)
        if not src_ip or not dst_ip:
            return []

        tcp = pkt[TCP]
        try:
            raw_flags = int(tcp.flags)
            sport = int(tcp.sport)
            dport = int(tcp.dport)
        except (TypeError, ValueError):
            return []

        core_flags = raw_flags & _CORE_FLAG_MASK

        # Exclude completed TCP handshakes when track_half_open_only is enabled.
        # Client ACK without SYN ((ACK != 0) and (SYN == 0)) completes the 3-way handshake.
        if self.config.track_half_open_only and (core_flags & _ACK) != 0 and (core_flags & _SYN) == 0:
            self._record_handshake_ack(src_ip, sport, dst_ip, dport, pkt_ts)
            return []

        classification = self._classify_probe(core_flags)
        if classification is None:
            return []

        scan_type, alert_type, severity, threshold = classification
        self.port_hits[dport] += 1

        # Skip SYN probe if this exact 4-tuple already completed a handshake within window
        if scan_type == "SYN" and self.config.track_half_open_only:
            completed_ts = self._completed_flows.get((src_ip, sport, dst_ip, dport))
            if completed_ts is not None and abs(pkt_ts - completed_ts) <= self.config.scan_window_seconds:
                return []

        key = (scan_type, src_ip, dst_ip)
        prev_hw = self._high_water_ts.get(key)
        window_sec = self.config.scan_window_seconds

        # Stale out-of-order packet older than active window horizon
        if prev_hw is not None and pkt_ts < (prev_hw - window_sec):
            return []

        hw = pkt_ts if prev_hw is None or pkt_ts > prev_hw else prev_hw
        self._high_water_ts[key] = hw

        win = self._windows[key]
        item = (pkt_ts, dport, sport)
        if not win or pkt_ts >= win[-1][0]:
            win.append(item)
        else:
            # Minor out-of-order packet inside active window: insert in timestamp order
            timestamps = [e[0] for e in win]
            idx = bisect.bisect_right(timestamps, pkt_ts)
            win.insert(idx, item)

        # Evict expired entries strictly older than (hw - window_sec)
        cutoff = hw - window_sec
        while win and win[0][0] < cutoff:
            win.pop(0)

        unique_ports = sorted({entry[1] for entry in win})
        if len(unique_ports) < threshold:
            return []

        cooldown_key = (alert_type, src_ip, dst_ip)
        last_alert = self._last_alert_ts.get(cooldown_key)
        if last_alert is not None and (hw - last_alert) < self.config.alert_cooldown_seconds:
            return []

        self._last_alert_ts[cooldown_key] = hw
        src_mac, dst_mac = extract_mac_pair(pkt)

        alert = Alert(
            alert_id=self._next_alert_id("SCAN"),
            timestamp=format_utc_timestamp(hw),
            packet_timestamp=hw,
            detector=self.name,
            alert_type=alert_type,
            severity=severity,
            mitre_attack=_MITRE_PORT_SCAN,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            summary=(
                f"{scan_type} port scan detected from {src_ip} against {dst_ip}: "
                f"{len(unique_ports)} unique ports probed within {window_sec:g}s"
            ),
            evidence={
                "scan_type": scan_type,
                "unique_port_count": len(unique_ports),
                "threshold": threshold,
                "window_seconds": window_sec,
                "packet_count_in_window": len(win),
                "sample_ports": unique_ports[:25],
                "tcp_flags_hex": f"0x{core_flags:02x}",
                "raw_tcp_flags_hex": f"0x{raw_flags:02x}",
                "half_open_only": self.config.track_half_open_only,
            },
        )
        return [alert]

    def get_top_targeted_ports(self, limit: int = 12) -> list[dict[str, int]]:
        """Return most frequently probed TCP destination ports."""
        return [
            {"port": port, "hits": hits}
            for port, hits in self.port_hits.most_common(limit)
        ]
