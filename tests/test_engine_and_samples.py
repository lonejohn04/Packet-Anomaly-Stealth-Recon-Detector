"""End-to-end engine, error-handling, config validation, and sample PCAP tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netguard import DetectorConfig, PacketAnalyzer, PcapReadError, QuarantineConfig
from conftest import BASE_TS


def test_config_validation_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        DetectorConfig(scan_window_seconds=0)
    with pytest.raises(ValueError):
        DetectorConfig(syn_scan_port_threshold=0)
    with pytest.raises(ValueError):
        DetectorConfig(dns_entropy_threshold=-1.0)
    with pytest.raises(ValueError):
        DetectorConfig(arp_static_bindings={"not-an-ip": "aa:bb:cc:dd:ee:ff"})
    with pytest.raises(ValueError):
        DetectorConfig(arp_static_bindings={"192.168.1.1": "invalid-mac"})
    with pytest.raises(ValueError):
        DetectorConfig.from_dict({"unknown_flag": 123})

    with pytest.raises(ValueError):
        QuarantineConfig(min_severity="EXTREME")
    with pytest.raises(ValueError):
        QuarantineConfig(table_name="bad;name")
    with pytest.raises(ValueError):
        QuarantineConfig(allowlist_cidrs=("not-a-cidr",))


def test_pcap_error_edge_cases(tmp_path: Path) -> None:
    analyzer = PacketAnalyzer()

    # Missing file
    with pytest.raises(PcapReadError):
        analyzer.analyze_pcap(tmp_path / "does_not_exist.pcap")

    # 0-byte empty file
    empty_file = tmp_path / "zero.pcap"
    empty_file.write_bytes(b"")
    with pytest.raises(PcapReadError):
        analyzer.analyze_pcap(empty_file)

    # Corrupted non-PCAP bytes
    corrupt_file = tmp_path / "corrupt.pcap"
    corrupt_file.write_bytes(b"definitely-not-a-valid-pcap-header-payload")
    with pytest.raises(PcapReadError):
        analyzer.analyze_pcap(corrupt_file)

    # Valid empty PCAP (24-byte header, 0 packets) returns clean zero-packet result
    valid_empty = tmp_path / "valid_empty.pcap"
    wrpcap(str(valid_empty), [])
    res = analyzer.analyze_pcap(valid_empty)
    assert res.total_packets == 0
    assert res.alerts == []


def test_non_ip_and_icmp_packets_in_memory() -> None:
    pkt_raw_ether = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff", type=0x88B5)
    pkt_raw_ether.time = BASE_TS
    pkt_icmp = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    pkt_icmp.time = BASE_TS + 1

    res = PacketAnalyzer().analyze_packets([pkt_raw_ether, pkt_icmp])
    assert res.total_packets == 2
    assert res.protocol_counts["Other"] == 1
    assert res.protocol_counts["ICMP"] == 1
    assert res.alerts == []


def test_all_six_generated_sample_pcaps(generated_samples_dir: Path) -> None:
    q_cfg = QuarantineConfig(enabled=True, dry_run=True)

    # 01: Stealth port scans (all 4 types, benign completed handshakes ignored)
    r1 = PacketAnalyzer(quarantine_config=q_cfg).analyze_pcap(generated_samples_dir / "01_stealth_port_scans.pcap")
    types1 = {a.alert_type for a in r1.alerts}
    assert types1 == {"TCP_SYN_SCAN", "TCP_FIN_SCAN", "TCP_NULL_SCAN", "TCP_XMAS_SCAN"}

    # 02: DNS tunneling
    r2 = PacketAnalyzer(quarantine_config=q_cfg).analyze_pcap(generated_samples_dir / "02_dns_tunneling.pcap")
    types2 = {a.alert_type for a in r2.alerts}
    assert types2 == {"DNS_HIGH_ENTROPY", "DNS_TXT_TUNNELING", "DNS_LONG_SUBDOMAIN"}
    assert len(r2.alerts) == 5

    # 03: ARP spoofing
    r3 = PacketAnalyzer(quarantine_config=q_cfg).analyze_pcap(generated_samples_dir / "03_arp_spoofing.pcap")
    types3 = {a.alert_type for a in r3.alerts}
    assert types3 == {"ARP_IP_MAC_CONFLICT", "ARP_HEADER_MISMATCH"}

    # 04: Full kill chain
    r4 = PacketAnalyzer(quarantine_config=q_cfg).analyze_pcap(generated_samples_dir / "04_full_killchain_demo.pcap")
    types4 = {a.alert_type for a in r4.alerts}
    assert {"TCP_SYN_SCAN", "TCP_XMAS_SCAN", "ARP_IP_MAC_CONFLICT", "DNS_HIGH_ENTROPY", "DNS_TXT_TUNNELING"} == types4

    # 05: Benign baseline -> strictly ZERO alerts
    r5 = PacketAnalyzer(quarantine_config=q_cfg).analyze_pcap(generated_samples_dir / "05_benign_baseline.pcap")
    assert r5.total_packets > 100
    assert r5.alerts == []

    # 06: Edge cases stress (default 10s window vs 60s window)
    r6_default = PacketAnalyzer(quarantine_config=q_cfg).analyze_pcap(generated_samples_dir / "06_edge_cases_stress.pcap")
    srcs_default = {a.src_ip for a in r6_default.alerts}
    assert "2001:db8:dead::42" in srcs_default
    assert "127.0.0.1" in srcs_default
    assert "192.0.2.77" not in srcs_default
    loopback_alert = [a for a in r6_default.alerts if a.src_ip == "127.0.0.1"][0]
    assert loopback_alert.quarantine_action == "skipped_allowlisted"

    r6_wide = PacketAnalyzer(
        detector_config=DetectorConfig(scan_window_seconds=60.0),
        quarantine_config=q_cfg,
    ).analyze_pcap(generated_samples_dir / "06_edge_cases_stress.pcap")
    assert "192.0.2.77" in {a.src_ip for a in r6_wide.alerts}
