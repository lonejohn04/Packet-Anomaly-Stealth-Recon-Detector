"""Base detector interface and shared packet metadata extraction helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from ..models import Alert


def format_utc_timestamp(ts: float) -> str:
    """Format a POSIX epoch timestamp as ISO-8601 UTC with millisecond precision."""
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        dt = datetime.fromtimestamp(0.0, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def extract_ip_pair(pkt: Any) -> tuple[str | None, str | None]:
    """Return (src_ip, dst_ip) for IPv4 or IPv6 packets, else (None, None)."""
    if IP in pkt:
        ip_layer = pkt[IP]
        return str(ip_layer.src), str(ip_layer.dst)
    if IPv6 in pkt:
        ip6_layer = pkt[IPv6]
        return str(ip6_layer.src), str(ip6_layer.dst)
    return None, None


def extract_mac_pair(pkt: Any) -> tuple[str | None, str | None]:
    """Return normalized lowercase (src_mac, dst_mac) from Ethernet header if present."""
    if Ether in pkt:
        eth = pkt[Ether]
        src = str(eth.src).lower() if getattr(eth, "src", None) else None
        dst = str(eth.dst).lower() if getattr(eth, "dst", None) else None
        return src, dst
    return None, None


class BaseDetector(ABC):
    """Abstract base class for stateful NetGuard protocol detectors."""

    name: str = "base"

    def __init__(self) -> None:
        self._alert_seq = 0

    def _next_alert_id(self, tag: str) -> str:
        self._alert_seq += 1
        return f"NG-{tag}-{self._alert_seq:04d}"

    @abstractmethod
    def process_packet(self, pkt: Any, pkt_ts: float) -> list[Alert]:
        """Inspect one packet and return zero or more Alert instances."""

    @abstractmethod
    def reset(self) -> None:
        """Reset all stateful tracking tables and counters."""
