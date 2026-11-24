"""Edge-case tests for PortScanDetector."""

from __future__ import annotations

from netguard.config import DetectorConfig
from netguard.detectors.port_scan import PortScanDetector
from conftest import BASE_TS, make_tcp_pkt


def test_syn_scan_exact_threshold_boundary() -> None:
    cfg = DetectorConfig(syn_scan_port_threshold=5, scan_window_seconds=10.0)
    det = PortScanDetector(cfg)

    # First 4 unique ports -> below threshold (0 alerts)
    for i in range(4):
        assert det.process_packet(make_tcp_pkt(dport=100 + i, ts=BASE_TS + i), BASE_TS + i) == []

    # 5th unique port -> triggers TCP_SYN_SCAN
    alerts = det.process_packet(make_tcp_pkt(dport=104, ts=BASE_TS + 4), BASE_TS + 4)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "TCP_SYN_SCAN"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["unique_port_count"] == 5


def test_completed_handshakes_excluded_when_half_open_only() -> None:
    cfg = DetectorConfig(syn_scan_port_threshold=5, track_half_open_only=True)
    det = PortScanDetector(cfg)

    # 10 sequential completed 3-way handshakes across 10 different ports -> 0 alerts
    for i in range(10):
        t = BASE_TS + i * 0.5
        sport = 40000 + i
        dport = 8000 + i
        assert det.process_packet(make_tcp_pkt(sport=sport, dport=dport, flags="S", ts=t), t) == []
        assert det.process_packet(
            make_tcp_pkt(src_ip="10.0.0.10", dst_ip="10.0.0.50", sport=dport, dport=sport, flags="SA", ts=t + 0.01),
            t + 0.01,
        ) == []
        assert det.process_packet(make_tcp_pkt(sport=sport, dport=dport, flags="A", ts=t + 0.02), t + 0.02) == []

    # Verify disabling track_half_open_only DOES trigger on the same pattern
    det_all = PortScanDetector(DetectorConfig(syn_scan_port_threshold=5, track_half_open_only=False))
    fired = []
    for i in range(5):
        t = BASE_TS + i * 0.2
        fired.extend(det_all.process_packet(make_tcp_pkt(sport=41000 + i, dport=9000 + i, flags="S", ts=t), t))
        fired.extend(det_all.process_packet(make_tcp_pkt(sport=41000 + i, dport=9000 + i, flags="A", ts=t + 0.02), t + 0.02))
    assert len(fired) == 1
    assert fired[0].alert_type == "TCP_SYN_SCAN"


def test_retransmissions_to_same_port_do_not_alert() -> None:
    det = PortScanDetector(DetectorConfig(syn_scan_port_threshold=5))
    for i in range(30):
        alerts = det.process_packet(make_tcp_pkt(sport=50000 + i, dport=443, flags="S", ts=BASE_TS + i * 0.1), BASE_TS + i * 0.1)
        assert alerts == []


def test_sliding_window_expiration() -> None:
    cfg = DetectorConfig(syn_scan_port_threshold=5, scan_window_seconds=10.0)
    det = PortScanDetector(cfg)

    # 4 ports at t=0..3s
    for i in range(4):
        assert det.process_packet(make_tcp_pkt(dport=200 + i, ts=BASE_TS + i), BASE_TS + i) == []

    # 1 port at t=15s -> earlier ports at t=0..3s have expired outside 10s window
    assert det.process_packet(make_tcp_pkt(dport=204, ts=BASE_TS + 15.0), BASE_TS + 15.0) == []


def test_out_of_order_and_stale_timestamps() -> None:
    cfg = DetectorConfig(syn_scan_port_threshold=4, scan_window_seconds=10.0)
    det = PortScanDetector(cfg)

    # Advance high-water timestamp to t=20
    assert det.process_packet(make_tcp_pkt(dport=1001, ts=BASE_TS + 20.0), BASE_TS + 20.0) == []
    # Stale packet from t=5 (< 20 - 10) must be ignored cleanly
    for i in range(5):
        assert det.process_packet(make_tcp_pkt(dport=1002 + i, ts=BASE_TS + 5.0 + i * 0.1), BASE_TS + 5.0 + i * 0.1) == []

    # Minor out-of-order packets inside [10, 20] DO count toward threshold
    assert det.process_packet(make_tcp_pkt(dport=1010, ts=BASE_TS + 18.0), BASE_TS + 18.0) == []
    assert det.process_packet(make_tcp_pkt(dport=1011, ts=BASE_TS + 17.5), BASE_TS + 17.5) == []
    alerts = det.process_packet(make_tcp_pkt(dport=1012, ts=BASE_TS + 19.0), BASE_TS + 19.0)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "TCP_SYN_SCAN"


def test_ecn_masked_syn_and_benign_flags() -> None:
    cfg = DetectorConfig(syn_scan_port_threshold=3, stealth_scan_port_threshold=3)
    det = PortScanDetector(cfg)

    # SYN|ECE|CWR ("SEC" = 0xC2 -> masked 0x02) must still be recognized as SYN scan
    alerts = []
    for i in range(3):
        alerts.extend(det.process_packet(make_tcp_pkt(dport=300 + i, flags="SEC", ts=BASE_TS + i * 0.1), BASE_TS + i * 0.1))
    assert len(alerts) == 1
    assert alerts[0].evidence["tcp_flags_hex"] == "0x02"
    assert alerts[0].evidence["raw_tcp_flags_hex"] == "0xc2"

    # SYN+ACK and FIN+ACK across many ports must NOT trigger scan alerts
    det2 = PortScanDetector(cfg)
    for i in range(10):
        assert det2.process_packet(make_tcp_pkt(dport=400 + i, flags="SA", ts=BASE_TS + i * 0.1), BASE_TS + i * 0.1) == []
        assert det2.process_packet(make_tcp_pkt(dport=500 + i, flags="FA", ts=BASE_TS + i * 0.1), BASE_TS + i * 0.1) == []


def test_stealth_fin_null_xmas_and_ipv6_and_cooldown() -> None:
    cfg = DetectorConfig(stealth_scan_port_threshold=3, syn_scan_port_threshold=3, alert_cooldown_seconds=30.0)
    det = PortScanDetector(cfg)

    for expected_type, flag in [("TCP_FIN_SCAN", "F"), ("TCP_NULL_SCAN", 0), ("TCP_XMAS_SCAN", "FPU")]:
        found = []
        for i in range(5):
            found.extend(
                det.process_packet(
                    make_tcp_pkt(src_ip="198.51.100.10", dport=700 + i, flags=flag, ts=BASE_TS + i * 0.1),
                    BASE_TS + i * 0.1,
                )
            )
        # Cooldown collapses burst of 5 ports into 1 alert
        assert len(found) == 1
        assert found[0].alert_type == expected_type
        assert found[0].severity == "CRITICAL"

    # Re-scan after cooldown >= 30s should emit a second alert
    re_alerts = []
    for i in range(3):
        re_alerts.extend(
            det.process_packet(
                make_tcp_pkt(src_ip="198.51.100.10", dport=750 + i, flags="F", ts=BASE_TS + 35.0 + i * 0.1),
                BASE_TS + 35.0 + i * 0.1,
            )
        )
    assert len(re_alerts) == 1
    assert re_alerts[0].alert_type == "TCP_FIN_SCAN"

    # IPv6 SYN scan
    v6_alerts = []
    for i in range(3):
        v6_alerts.extend(
            det.process_packet(
                make_tcp_pkt(
                    src_ip="2001:db8:dead::9",
                    dst_ip="2001:db8:cafe::1",
                    dport=80 + i,
                    flags="S",
                    ts=BASE_TS + i * 0.1,
                    ipv6=True,
                ),
                BASE_TS + i * 0.1,
            )
        )
    assert len(v6_alerts) == 1
    assert v6_alerts[0].src_ip == "2001:db8:dead::9"
