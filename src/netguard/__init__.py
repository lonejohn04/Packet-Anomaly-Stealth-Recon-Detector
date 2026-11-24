"""NetGuard: Python & Scapy Network Packet Anomaly and Stealth Recon Detector."""

from __future__ import annotations

from .config import DetectorConfig, QuarantineConfig
from .engine import PacketAnalyzer, PcapReadError

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "DetectorConfig",
    "QuarantineConfig",
    "PacketAnalyzer",
    "PcapReadError",
]
