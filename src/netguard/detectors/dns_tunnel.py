"""Shannon-entropy and length-based DNS tunneling & exfiltration detector."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from scapy.layers.dns import DNS, DNSQR

from ..config import DetectorConfig
from ..models import Alert, DnsObservation, MitreMapping
from .base import BaseDetector, extract_ip_pair, extract_mac_pair, format_utc_timestamp

_MITRE_DNS_C2 = MitreMapping(
    tactic="Command and Control",
    technique_id="T1071.004",
    technique_name="Application Layer Protocol: DNS",
)

_MITRE_DNS_EXFIL = MitreMapping(
    tactic="Exfiltration",
    technique_id="T1048.003",
    technique_name="Exfiltration Over Unencrypted Non-C2 Protocol",
)

_TWO_PART_TLDS = frozenset({
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "com.br",
    "co.nz",
    "com.sg",
})

_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}


def shannon_entropy(data: str) -> float:
    """Compute base-2 Shannon entropy in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def split_domain(qname: str) -> tuple[str, str]:
    """Split an FQDN into (subdomain, base_domain), preserving subdomain case."""
    cleaned = qname.strip().rstrip(".")
    if not cleaned:
        return "", ""
    labels = [lbl for lbl in cleaned.split(".") if lbl]
    if len(labels) <= 1:
        return "", cleaned.lower()

    if len(labels) >= 3 and ".".join(labels[-2:]).lower() in _TWO_PART_TLDS:
        base = ".".join(labels[-3:]).lower()
        sub = ".".join(labels[:-3])
        return sub, base

    base = ".".join(labels[-2:]).lower()
    sub = ".".join(labels[:-2])
    return sub, base


def _decode_qname(raw_qname: Any) -> str:
    """Safely decode DNS qname bytes or string without raising on malformed bytes."""
    if raw_qname is None:
        return ""
    if isinstance(raw_qname, bytes):
        text = raw_qname.decode("utf-8", errors="replace")
    else:
        text = str(raw_qname)
    return text.replace("\x00", "").strip().rstrip(".")


class DnsTunnelDetector(BaseDetector):
    """Detects high-entropy DNS subdomains and oversized TXT/subdomain tunneling queries."""

    name = "dns_tunnel"
    _MAX_OBSERVATIONS = 500

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__()
        self.config = config or DetectorConfig()
        # (src_ip, fqdn_lower, alert_type) -> last alert packet timestamp
        self._last_alert_ts: dict[tuple[str | None, str, str], float] = {}
        self.observations: list[DnsObservation] = []

    def reset(self) -> None:
        self._alert_seq = 0
        self._last_alert_ts.clear()
        self.observations.clear()

    def _is_allowlisted(self, fqdn_lower: str) -> bool:
        """Return True if domain matches benign suffixes, prefixes, or explicit allowlist."""
        if "." not in fqdn_lower:
            return True
        for prefix in self.config.dns_ignore_prefixes:
            if fqdn_lower.startswith(prefix):
                return True
        for suffix in self.config.dns_allowlist_suffixes:
            if fqdn_lower == suffix or fqdn_lower.endswith("." + suffix):
                return True
        for domain in self.config.dns_allowlist_domains:
            if fqdn_lower == domain or fqdn_lower.endswith("." + domain):
                return True
        return False

    def _iter_questions(self, dns: DNS) -> list[DNSQR]:
        """Safely extract DNSQR question records from a DNS layer."""
        questions: list[DNSQR] = []
        try:
            qdcount = int(getattr(dns, "qdcount", 0) or 0)
        except (TypeError, ValueError):
            qdcount = 0
        max_questions = max(1, min(qdcount, 16))
        qd = getattr(dns, "qd", None)
        if qd is None:
            return questions
        if isinstance(qd, (list, tuple)):
            for item in qd:
                if isinstance(item, DNSQR):
                    questions.append(item)
                    if len(questions) >= max_questions:
                        break
            return questions
        cur: Any = qd
        while cur is not None and isinstance(cur, DNSQR) and len(questions) < max_questions:
            questions.append(cur)
            cur = getattr(cur, "payload", None)
            if cur is not None and not isinstance(cur, DNSQR):
                break
        return questions

    def process_packet(self, pkt: Any, pkt_ts: float) -> list[Alert]:
        if DNS not in pkt:
            return []

        dns = pkt[DNS]
        try:
            if int(getattr(dns, "qr", 1)) != 0:
                return []
        except (TypeError, ValueError):
            return []

        questions = self._iter_questions(dns)
        if not questions:
            return []

        src_ip, dst_ip = extract_ip_pair(pkt)
        src_mac, dst_mac = extract_mac_pair(pkt)
        ts_iso = format_utc_timestamp(pkt_ts)
        alerts: list[Alert] = []

        for qr in questions:
            fqdn = _decode_qname(getattr(qr, "qname", None))
            if not fqdn:
                continue

            fqdn_lower = fqdn.lower()
            if self._is_allowlisted(fqdn_lower):
                continue

            try:
                qtype = int(getattr(qr, "qtype", 0))
            except (TypeError, ValueError):
                qtype = 0
            qtype_name = _QTYPE_NAMES.get(qtype, f"TYPE{qtype}")

            subdomain, base_domain = split_domain(fqdn)
            subdomain_nodots = subdomain.replace(".", "")
            entropy = round(shannon_entropy(subdomain_nodots), 4)
            sub_len = len(subdomain)
            fqdn_len = len(fqdn)

            is_txt = qtype == 16
            high_entropy = (
                len(subdomain_nodots) >= self.config.dns_min_subdomain_len
                and entropy >= self.config.dns_entropy_threshold
            )
            long_sub = (
                sub_len > self.config.dns_max_subdomain_len
                or fqdn_len > self.config.dns_max_fqdn_len
            )
            long_txt = is_txt and (
                sub_len >= self.config.dns_txt_length_threshold
                or fqdn_len >= (self.config.dns_txt_length_threshold + 15)
            )

            flagged = (is_txt and (high_entropy or long_txt or long_sub)) or high_entropy or long_sub

            if len(self.observations) < self._MAX_OBSERVATIONS:
                self.observations.append(
                    DnsObservation(
                        timestamp=ts_iso,
                        src_ip=src_ip,
                        qname=fqdn,
                        qtype=qtype_name,
                        subdomain=subdomain,
                        subdomain_len=sub_len,
                        entropy=entropy,
                        flagged=flagged,
                    )
                )

            if not flagged:
                continue

            triggers: list[str] = []
            if high_entropy:
                triggers.append("high_entropy")
            if sub_len > self.config.dns_max_subdomain_len:
                triggers.append("long_subdomain")
            if fqdn_len > self.config.dns_max_fqdn_len:
                triggers.append("long_fqdn")
            if long_txt:
                triggers.append("long_txt_query")

            if is_txt and (high_entropy or long_txt or long_sub):
                alert_type = "DNS_TXT_TUNNELING"
                severity = "CRITICAL"
                mitre = _MITRE_DNS_EXFIL
                if "txt_record" not in triggers:
                    triggers.append("txt_record")
                summary = (
                    f"Suspected DNS TXT tunneling from {src_ip or 'unknown'}: "
                    f"{fqdn[:72]} (entropy={entropy:.2f}, sub_len={sub_len})"
                )
            elif high_entropy:
                alert_type = "DNS_HIGH_ENTROPY"
                severity = "HIGH"
                mitre = _MITRE_DNS_C2
                summary = (
                    f"High-entropy DNS subdomain query from {src_ip or 'unknown'}: "
                    f"{fqdn[:72]} (entropy={entropy:.2f}, sub_len={sub_len})"
                )
            else:
                alert_type = "DNS_LONG_SUBDOMAIN"
                severity = "MEDIUM" if sub_len <= 80 else "HIGH"
                mitre = _MITRE_DNS_C2
                summary = (
                    f"Unusually long DNS subdomain query from {src_ip or 'unknown'}: "
                    f"{fqdn[:72]} (sub_len={sub_len}, fqdn_len={fqdn_len})"
                )

            cooldown_key = (src_ip, fqdn_lower, alert_type)
            last_ts = self._last_alert_ts.get(cooldown_key)
            if (
                last_ts is not None
                and pkt_ts >= last_ts
                and (pkt_ts - last_ts) < self.config.alert_cooldown_seconds
            ):
                continue
            self._last_alert_ts[cooldown_key] = pkt_ts

            alerts.append(
                Alert(
                    alert_id=self._next_alert_id("DNS"),
                    timestamp=ts_iso,
                    packet_timestamp=pkt_ts,
                    detector=self.name,
                    alert_type=alert_type,
                    severity=severity,
                    mitre_attack=mitre,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    summary=summary,
                    evidence={
                        "qname": fqdn,
                        "base_domain": base_domain,
                        "subdomain": subdomain,
                        "qtype": qtype,
                        "qtype_name": qtype_name,
                        "subdomain_length": sub_len,
                        "fqdn_length": fqdn_len,
                        "shannon_entropy": entropy,
                        "entropy_threshold": self.config.dns_entropy_threshold,
                        "triggers": triggers,
                    },
                )
            )

        return alerts
