"""Edge-case tests for DnsTunnelDetector."""

from __future__ import annotations

import math

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from netguard.config import DetectorConfig
from netguard.detectors.dns_tunnel import DnsTunnelDetector, shannon_entropy, split_domain
from conftest import BASE_TS, make_dns_pkt


def test_shannon_entropy_and_split_domain() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert math.isclose(shannon_entropy("ab"), 1.0, rel_tol=1e-6)
    assert shannon_entropy("9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9M") > 4.5

    assert split_domain("www.example.com.") == ("www", "example.com")
    assert split_domain("aB3xY9.sub.example.co.uk.") == ("aB3xY9.sub", "example.co.uk")
    assert split_domain("localhost.") == ("", "localhost")


def test_short_random_subdomain_does_not_alert() -> None:
    det = DnsTunnelDetector(DetectorConfig())
    # 10 chars < dns_min_subdomain_len=20 -> must NOT trigger entropy false positive
    assert det.process_packet(make_dns_pkt("x9k2m7p4q1.example.com", "A"), BASE_TS) == []


def test_high_entropy_and_long_low_entropy_and_consolidated_txt() -> None:
    det = DnsTunnelDetector(DetectorConfig())

    # 1. High entropy A query -> DNS_HIGH_ENTROPY
    a1 = det.process_packet(
        make_dns_pkt("9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.c2.evil.test", "A", ts=BASE_TS),
        BASE_TS,
    )
    assert len(a1) == 1
    assert a1[0].alert_type == "DNS_HIGH_ENTROPY"
    assert a1[0].severity == "HIGH"

    # 2. Low-entropy long subdomain -> DNS_LONG_SUBDOMAIN
    a2 = det.process_packet(
        make_dns_pkt("a1" * 30 + ".tunnel.evil.test", "A", ts=BASE_TS + 1),
        BASE_TS + 1,
    )
    assert len(a2) == 1
    assert a2[0].alert_type == "DNS_LONG_SUBDOMAIN"
    assert a2[0].severity == "MEDIUM"

    # 3. TXT matching high_entropy + long_txt + long_sub -> strictly ONE consolidated alert
    a3 = det.process_packet(
        make_dns_pkt(
            "ZXhmaWwtY2h1bmstMDAxLWtleS1hOWI4Yzd2NmU1cjR0M3kyLmpz.exfil.evil.test",
            "TXT",
            ts=BASE_TS + 2,
        ),
        BASE_TS + 2,
    )
    assert len(a3) == 1
    assert a3[0].alert_type == "DNS_TXT_TUNNELING"
    assert a3[0].severity == "CRITICAL"
    assert "txt_record" in a3[0].evidence["triggers"]
    assert "high_entropy" in a3[0].evidence["triggers"]


def test_allowlists_responses_tcp_ipv6_and_malformed_dns() -> None:
    cfg = DetectorConfig(dns_allowlist_domains=("trusted-cdn.net",))
    det = DnsTunnelDetector(cfg)

    # Reverse PTR, IPv6 PTR, .local mDNS, _dmarc, custom allowlisted CDN -> 0 alerts
    benign = [
        ("4.3.2.1.10.20.30.40.50.60.in-addr.arpa", "PTR"),
        ("1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.ip6.arpa", "PTR"),
        ("9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.local", "A"),
        ("_dmarc.9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.example.com", "TXT"),
        ("9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.edge.trusted-cdn.net", "A"),
    ]
    for idx, (qname, qtype) in enumerate(benign):
        assert det.process_packet(make_dns_pkt(qname, qtype, ts=BASE_TS + idx), BASE_TS + idx) == []

    # DNS response (qr=1) must be ignored
    assert det.process_packet(
        make_dns_pkt("9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.evil.test", "TXT", qr=1, ts=BASE_TS + 10),
        BASE_TS + 10,
    ) == []

    # DNS over TCP & IPv6 must still be detected
    tcp_alerts = det.process_packet(
        make_dns_pkt(
            "9Kx2Lm8Qp4Zr7Wv1Yt5Bn3Cd6Fg0Hj9Mk4Pq.tcp.evil.test",
            "A",
            over_tcp=True,
            ipv6=True,
            src_ip="2001:db8::25",
            dst_ip="2001:db8::2",
            ts=BASE_TS + 11,
        ),
        BASE_TS + 11,
    )
    assert len(tcp_alerts) == 1
    assert tcp_alerts[0].src_ip == "2001:db8::25"

    # Malformed packets: missing DNSQR, empty qname, non-UTF8 bytes -> never crash
    pkt_no_qd = Ether() / IP() / UDP(dport=53) / DNS(qr=0, qdcount=1, qd=[])
    assert det.process_packet(pkt_no_qd, BASE_TS + 12) == []

    pkt_empty_qname = make_dns_pkt(b"", "A", ts=BASE_TS + 13)
    assert det.process_packet(pkt_empty_qname, BASE_TS + 13) == []

    pkt_non_utf8 = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.5", dst="10.0.0.2")
        / UDP(sport=5000, dport=53)
        / DNS(qr=0, qd=[])
        / Raw(b"\xff\xfe\xfd\x00")
    )
    assert det.process_packet(pkt_non_utf8, BASE_TS + 14) == []
