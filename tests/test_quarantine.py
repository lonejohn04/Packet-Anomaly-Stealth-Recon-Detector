"""Edge-case tests for NftablesQuarantineManager."""

from __future__ import annotations

import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from netguard.config import QuarantineConfig
from netguard.models import Alert, MitreMapping
from netguard.quarantine import NftablesQuarantineManager


def _make_alert(src_ip: str | None, severity: str = "CRITICAL", alert_id: str = "NG-TEST-0001") -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp="2023-11-14T22:13:20.000Z",
        packet_timestamp=1700000000.0,
        detector="port_scan",
        alert_type="TCP_SYN_SCAN",
        severity=severity,
        mitre_attack=MitreMapping("Discovery", "T1046", "Network Service Discovery"),
        src_ip=src_ip,
        dst_ip="192.168.10.10",
        src_mac=None,
        dst_mac=None,
        summary="Test alert",
    )


def test_ip_validation_rejects_injection_and_garbage() -> None:
    mgr = NftablesQuarantineManager(QuarantineConfig(enabled=True, dry_run=True))
    for bad in [None, "", "not-an-ip", "203.0.113.1; rm -rf /", "203.0.113.1 && id", "203.0.113.1\n"]:
        assert mgr.validate_ip(bad) is None

    rec = mgr.evaluate_alert(_make_alert("203.0.113.1; id"))
    assert rec is not None
    assert rec.status == "invalid_ip"


@pytest.mark.parametrize(
    "protected_ip",
    [
        "127.0.0.1",
        "127.255.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "ff02::1",
        "10.20.30.40",  # covered by custom allowlist CIDR below
    ],
)
def test_builtin_safety_nets_and_custom_allowlist(protected_ip: str) -> None:
    cfg = QuarantineConfig(enabled=True, dry_run=True, allowlist_cidrs=("10.20.0.0/16",))
    mgr = NftablesQuarantineManager(cfg)
    alert = _make_alert(protected_ip)
    rec = mgr.evaluate_alert(alert)
    assert rec is not None
    assert rec.status == "skipped_allowlisted"
    assert alert.quarantine_action == "skipped_allowlisted"


def test_dry_run_ipv4_ipv6_dedup_and_ruleset() -> None:
    cfg = QuarantineConfig(enabled=True, dry_run=True, timeout_seconds=600, min_severity="HIGH")
    mgr = NftablesQuarantineManager(cfg)

    ruleset = mgr.generate_bootstrap_ruleset()
    assert "table inet netguard" in ruleset
    assert "set blocked_ipv4" in ruleset
    assert "set blocked_ipv6" in ruleset
    assert "flags timeout" in ruleset

    # Below min_severity -> ignored
    low_alert = _make_alert("203.0.113.10", severity="MEDIUM")
    assert mgr.evaluate_alert(low_alert) is None
    assert low_alert.quarantine_action == "none"

    # IPv4 dry-run block
    a4 = _make_alert("203.0.113.10", severity="HIGH", alert_id="A1")
    r4 = mgr.evaluate_alert(a4)
    assert r4 is not None
    assert r4.status == "dry_run"
    assert r4.family == "ipv4"
    assert "blocked_ipv4 { 203.0.113.10 timeout 600s }" in r4.commands[-1]

    # Duplicate IP suppressed
    a4_dup = _make_alert("203.0.113.10", severity="CRITICAL", alert_id="A2")
    assert mgr.evaluate_alert(a4_dup) is None
    assert a4_dup.quarantine_action == "dry_run"

    # IPv6 dry-run block
    a6 = _make_alert("2001:db8:dead::42", severity="CRITICAL", alert_id="A3")
    r6 = mgr.evaluate_alert(a6)
    assert r6 is not None
    assert r6.family == "ipv6"
    assert "blocked_ipv6 { 2001:db8:dead::42 timeout 600s }" in r6.commands[-1]

    ok, active = mgr.list_active_blocks()
    assert ok is True
    assert sorted(active) == ["2001:db8:dead::42", "203.0.113.10"]

    ok_u, _ = mgr.unblock_ip("203.0.113.10")
    assert ok_u is True
    ok_f, _ = mgr.flush_table()
    assert ok_f is True


def test_live_mode_handles_missing_nft_non_root_and_mocked_success(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = QuarantineConfig(enabled=True, dry_run=False, timeout_seconds=300)

    # 1. Missing nft binary
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    mgr1 = NftablesQuarantineManager(cfg)
    r1 = mgr1.evaluate_alert(_make_alert("203.0.113.50"))
    assert r1 is not None and r1.status == "failed"
    assert "not found" in r1.detail

    # 2. Non-root user
    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/bin/nft")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    mgr2 = NftablesQuarantineManager(cfg)
    r2 = mgr2.evaluate_alert(_make_alert("203.0.113.51"))
    assert r2 is not None and r2.status == "failed"
    assert "root privileges" in r2.detail

    # 3. Mocked root + working nft
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(subprocess, "run", fake_run)
    mgr3 = NftablesQuarantineManager(cfg)
    r3 = mgr3.evaluate_alert(_make_alert("203.0.113.52"))
    assert r3 is not None and r3.status == "applied"
    assert calls[0] == ["nft", "-f", "-"]
    assert calls[1] == [
        "nft", "add", "element", "inet", "netguard", "blocked_ipv4", "{", "203.0.113.52", "timeout", "300s", "}"
    ]
