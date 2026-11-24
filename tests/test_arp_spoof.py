"""Edge-case tests for ArpSpoofDetector."""

from __future__ import annotations

from netguard.config import DetectorConfig
from netguard.detectors.arp_spoof import ArpSpoofDetector
from conftest import BASE_TS, make_arp_pkt


def test_arp_baseline_and_conflict_preserves_original_mac() -> None:
    det = ArpSpoofDetector(DetectorConfig(alert_cooldown_seconds=30.0))

    assert det.process_packet(
        make_arp_pkt(psrc="192.168.10.1", hwsrc="aa:bb:cc:00:00:01", ts=BASE_TS), BASE_TS
    ) == []
    # Consistent repeat -> 0 alerts
    assert det.process_packet(
        make_arp_pkt(psrc="192.168.10.1", hwsrc="AA:BB:CC:00:00:01", ts=BASE_TS + 1), BASE_TS + 1
    ) == []

    # Spoofed gratuitous reply -> CRITICAL alert and original MAC stays intact
    alerts = det.process_packet(
        make_arp_pkt(
            op=2,
            psrc="192.168.10.1",
            pdst="192.168.10.1",
            hwsrc="de:ad:be:ef:13:37",
            ts=BASE_TS + 2,
        ),
        BASE_TS + 2,
    )
    assert len(alerts) == 1
    assert alerts[0].alert_type == "ARP_IP_MAC_CONFLICT"
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].evidence["original_mac"] == "aa:bb:cc:00:00:01"
    assert alerts[0].evidence["spoofed_mac"] == "de:ad:be:ef:13:37"
    assert alerts[0].evidence["is_gratuitous"] is True

    bindings = {b.ip: b for b in det.get_bindings()}
    assert bindings["192.168.10.1"].mac == "aa:bb:cc:00:00:01"
    assert bindings["192.168.10.1"].conflicts == 1
    assert bindings["192.168.10.1"].conflicting_macs == ["de:ad:be:ef:13:37"]


def test_arp_static_binding_catches_spoof_on_first_packet() -> None:
    cfg = DetectorConfig(arp_static_bindings={"192.168.10.1": "AA:BB:CC:00:00:01"})
    det = ArpSpoofDetector(cfg)

    alerts = det.process_packet(
        make_arp_pkt(psrc="192.168.10.1", hwsrc="de:ad:be:ef:99:99", ts=BASE_TS),
        BASE_TS,
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["is_static_binding"] is True
    assert alerts[0].evidence["original_mac"] == "aa:bb:cc:00:00:01"


def test_arp_probes_special_macs_ignored_ips_and_header_mismatch() -> None:
    cfg = DetectorConfig(arp_ignored_ips=("192.168.10.254",), arp_check_header_mismatch=True)
    det = ArpSpoofDetector(cfg)

    # RFC 5227 probe (0.0.0.0) & zero/broadcast MAC & ignored VRRP IP -> 0 alerts
    assert det.process_packet(make_arp_pkt(op=1, psrc="0.0.0.0", pdst="192.168.10.50", hwsrc="00:11:22:33:44:50", ts=BASE_TS), BASE_TS) == []
    assert det.process_packet(make_arp_pkt(op=2, psrc="192.168.10.50", hwsrc="00:00:00:00:00:00", ts=BASE_TS + 1), BASE_TS + 1) == []
    assert det.process_packet(make_arp_pkt(op=2, psrc="192.168.10.50", hwsrc="ff:ff:ff:ff:ff:ff", ts=BASE_TS + 2), BASE_TS + 2) == []
    assert det.process_packet(make_arp_pkt(op=2, psrc="192.168.10.254", hwsrc="00:00:5e:00:01:01", ts=BASE_TS + 3), BASE_TS + 3) == []
    assert det.process_packet(make_arp_pkt(op=2, psrc="192.168.10.254", hwsrc="00:00:5e:00:01:02", ts=BASE_TS + 4), BASE_TS + 4) == []
    assert det.get_bindings() == []

    # L2 Ethernet src != ARP hwsrc mismatch -> ARP_HEADER_MISMATCH
    mismatch = det.process_packet(
        make_arp_pkt(
            op=2,
            psrc="192.168.10.2",
            hwsrc="aa:bb:cc:00:00:02",
            eth_src="de:ad:be:ef:00:02",
            ts=BASE_TS + 5,
        ),
        BASE_TS + 5,
    )
    assert len(mismatch) == 1
    assert mismatch[0].alert_type == "ARP_HEADER_MISMATCH"
    assert mismatch[0].severity == "HIGH"
