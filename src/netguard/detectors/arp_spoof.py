"""Stateful ARP IP-to-MAC spoofing and L2 header mismatch detector."""

from __future__ import annotations

import ipaddress
from typing import Any

from scapy.layers.l2 import ARP

from ..config import DetectorConfig
from ..models import Alert, ArpBinding, MitreMapping
from .base import BaseDetector, extract_mac_pair, format_utc_timestamp

_MITRE_ARP = MitreMapping(
    tactic="Credential Access",
    technique_id="T1557.002",
    technique_name="Adversary-in-the-Middle: ARP Cache Poisoning",
)

_SPECIAL_MACS = frozenset({"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})
_ARP_OPS = {1: "who-has (request)", 2: "is-at (reply)"}


class ArpSpoofDetector(BaseDetector):
    """Detects duplicate IP-to-MAC ARP conflicts and Ethernet/ARP sender mismatches."""

    name = "arp_spoof"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__()
        self.config = config or DetectorConfig()
        self._bindings: dict[str, ArpBinding] = {}
        self._last_alert_ts: dict[tuple[str, ...], float] = {}
        self._seed_static_bindings()

    def _seed_static_bindings(self) -> None:
        """Populate ARP table with trusted static IP -> MAC ground truth."""
        for ip_str, mac_str in self.config.arp_static_bindings.items():
            self._bindings[ip_str] = ArpBinding(
                ip=ip_str,
                mac=mac_str,
                first_seen="static",
                last_seen="static",
                packet_count=0,
                is_static=True,
            )

    def reset(self) -> None:
        self._alert_seq = 0
        self._bindings.clear()
        self._last_alert_ts.clear()
        self._seed_static_bindings()

    def get_bindings(self) -> list[ArpBinding]:
        """Return observed and static ARP table entries sorted by IP."""
        return sorted(self._bindings.values(), key=lambda b: b.ip)

    def _cooldown_allows(self, key: tuple[str, ...], pkt_ts: float) -> bool:
        last_ts = self._last_alert_ts.get(key)
        if last_ts is not None and pkt_ts >= last_ts and (pkt_ts - last_ts) < self.config.alert_cooldown_seconds:
            return False
        self._last_alert_ts[key] = pkt_ts
        return True

    def process_packet(self, pkt: Any, pkt_ts: float) -> list[Alert]:
        if ARP not in pkt:
            return []

        arp = pkt[ARP]
        try:
            op = int(getattr(arp, "op", 0))
        except (TypeError, ValueError):
            return []

        psrc = str(getattr(arp, "psrc", "") or "").strip()
        pdst = str(getattr(arp, "pdst", "") or "").strip()
        hwsrc = str(getattr(arp, "hwsrc", "") or "").strip().lower()
        eth_src, eth_dst = extract_mac_pair(pkt)
        ts_iso = format_utc_timestamp(pkt_ts)
        alerts: list[Alert] = []

        # Validate psrc is a real IP address before evaluating bindings
        try:
            ipaddress.ip_address(psrc)
        except ValueError:
            psrc = ""

        # Check Ethernet source vs ARP sender hardware address mismatch (RFC 826 / anti-spoof)
        if (
            self.config.arp_check_header_mismatch
            and eth_src
            and hwsrc
            and eth_src not in _SPECIAL_MACS
            and hwsrc not in _SPECIAL_MACS
            and eth_src != hwsrc
        ):
            if self._cooldown_allows(("ARP_HEADER_MISMATCH", psrc or "unknown", eth_src, hwsrc), pkt_ts):
                alerts.append(
                    Alert(
                        alert_id=self._next_alert_id("ARP"),
                        timestamp=ts_iso,
                        packet_timestamp=pkt_ts,
                        detector=self.name,
                        alert_type="ARP_HEADER_MISMATCH",
                        severity="HIGH",
                        mitre_attack=_MITRE_ARP,
                        src_ip=psrc or None,
                        dst_ip=pdst or None,
                        src_mac=eth_src,
                        dst_mac=eth_dst,
                        summary=(
                            f"ARP L2 header mismatch: Ethernet src {eth_src} != ARP hwsrc {hwsrc}"
                            + (f" (claiming {psrc})" if psrc else "")
                        ),
                        evidence={
                            "eth_src_mac": eth_src,
                            "arp_hwsrc_mac": hwsrc,
                            "arp_psrc": psrc or None,
                            "arp_pdst": pdst or None,
                            "arp_op": op,
                            "arp_op_name": _ARP_OPS.get(op, f"op-{op}"),
                        },
                    )
                )

        # Ignore RFC 5227 Duplicate Address Detection (DAD) probes (psrc == 0.0.0.0),
        # invalid/broadcast hardware addresses, and explicitly ignored failover/VRRP IPs.
        if (
            not psrc
            or psrc == "0.0.0.0"
            or hwsrc in _SPECIAL_MACS
            or psrc in self.config.arp_ignored_ips
            or op not in (1, 2)
        ):
            return alerts

        binding = self._bindings.get(psrc)
        if binding is None:
            self._bindings[psrc] = ArpBinding(
                ip=psrc,
                mac=hwsrc,
                first_seen=ts_iso,
                last_seen=ts_iso,
                packet_count=1,
                is_static=False,
            )
            return alerts

        if binding.mac == hwsrc:
            if binding.first_seen == "static":
                binding.first_seen = ts_iso
            binding.last_seen = ts_iso
            binding.packet_count += 1
            return alerts

        # Conflict detected: keep original/static ground-truth MAC intact!
        binding.conflicts += 1
        binding.last_seen = ts_iso
        if hwsrc not in binding.conflicting_macs:
            binding.conflicting_macs.append(hwsrc)

        if self._cooldown_allows(("ARP_IP_MAC_CONFLICT", psrc, hwsrc), pkt_ts):
            is_gratuitous = bool(pdst and psrc == pdst)
            alerts.append(
                Alert(
                    alert_id=self._next_alert_id("ARP"),
                    timestamp=ts_iso,
                    packet_timestamp=pkt_ts,
                    detector=self.name,
                    alert_type="ARP_IP_MAC_CONFLICT",
                    severity="CRITICAL",
                    mitre_attack=_MITRE_ARP,
                    src_ip=psrc,
                    dst_ip=pdst or None,
                    src_mac=hwsrc,
                    dst_mac=eth_dst,
                    summary=(
                        f"ARP spoofing detected for {psrc}: MAC changed from "
                        f"{binding.mac} to {hwsrc}"
                        + (" (gratuitous ARP)" if is_gratuitous else "")
                    ),
                    evidence={
                        "ip": psrc,
                        "original_mac": binding.mac,
                        "spoofed_mac": hwsrc,
                        "arp_op": op,
                        "arp_op_name": _ARP_OPS.get(op, f"op-{op}"),
                        "is_gratuitous": is_gratuitous,
                        "is_static_binding": binding.is_static,
                        "conflict_count": binding.conflicts,
                    },
                )
            )

        return alerts
