"""Structured data models for NetGuard alerts, telemetry, and analysis reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_RANK: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class MitreMapping:
    """MITRE ATT&CK technique reference attached to security alerts."""

    tactic: str
    technique_id: str
    technique_name: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class Alert:
    """Structured security alert emitted by a packet detector."""

    alert_id: str
    timestamp: str
    packet_timestamp: float
    detector: str
    alert_type: str
    severity: str
    mitre_attack: MitreMapping
    src_ip: str | None
    dst_ip: str | None
    src_mac: str | None
    dst_mac: str | None
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    quarantine_action: str = "none"
    quarantine_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "packet_timestamp": self.packet_timestamp,
            "detector": self.detector,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "mitre_attack": self.mitre_attack.to_dict(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "summary": self.summary,
            "evidence": self.evidence,
            "quarantine_action": self.quarantine_action,
            "quarantine_detail": self.quarantine_detail,
        }


@dataclass
class ArpBinding:
    """Observed or statically configured IP-to-MAC mapping in the ARP table."""

    ip: str
    mac: str
    first_seen: str
    last_seen: str
    packet_count: int = 1
    is_static: bool = False
    conflicts: int = 0
    conflicting_macs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DnsObservation:
    """Telemetry record for an analyzed DNS query."""

    timestamp: str
    src_ip: str | None
    qname: str
    qtype: str
    subdomain: str
    subdomain_len: int
    entropy: float
    flagged: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class QuarantineRecord:
    """Audit record of an automated or simulated nftables quarantine evaluation."""

    ip: str
    family: str
    status: str
    reason: str
    alert_id: str
    timestamp: str
    timeout_seconds: int
    commands: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Complete result returned by PacketAnalyzer after PCAP or live capture."""

    source: str
    started_at: str
    finished_at: str
    duration_ms: float
    total_packets: int
    protocol_counts: dict[str, int]
    alerts: list[Alert]
    arp_table: list[ArpBinding]
    dns_observations: list[DnsObservation]
    top_targeted_ports: list[dict[str, Any]]
    timeline_buckets: list[dict[str, Any]]
    quarantine_records: list[QuarantineRecord]
    config: dict[str, Any]

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for alert in self.alerts:
            if alert.severity in counts:
                counts[alert.severity] += 1
        return counts

    @property
    def alert_type_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.alert_type] = counts.get(alert.alert_type, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": round(self.duration_ms, 2),
            "total_packets": self.total_packets,
            "alert_count": len(self.alerts),
            "severity_counts": self.severity_counts,
            "alert_type_counts": self.alert_type_counts,
            "protocol_counts": self.protocol_counts,
            "alerts": [a.to_dict() for a in self.alerts],
            "arp_table": [b.to_dict() for b in self.arp_table],
            "dns_observations": [d.to_dict() for d in self.dns_observations],
            "top_targeted_ports": self.top_targeted_ports,
            "timeline_buckets": self.timeline_buckets,
            "quarantine_records": [q.to_dict() for q in self.quarantine_records],
            "config": self.config,
        }
