"""CLI end-to-end tests for NetGuard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netguard.cli import main


def test_cli_generate_samples_and_analyze_json_jsonl(tmp_path: Path) -> None:
    samples_out = tmp_path / "samples"
    rc = main(["generate-samples", "--output-dir", str(samples_out)])
    assert rc == 0
    pcap_path = samples_out / "04_full_killchain_demo.pcap"
    assert pcap_path.is_file()

    json_out = tmp_path / "out" / "report.json"
    jsonl_out = tmp_path / "out" / "alerts.jsonl"
    rc2 = main([
        "analyze",
        str(pcap_path),
        "--quarantine",
        "--json",
        str(json_out),
        "--jsonl",
        str(jsonl_out),
        "--quiet",
    ])
    assert rc2 == 0
    assert json_out.is_file()
    assert jsonl_out.is_file()

    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["alert_count"] == 5
    lines = [json.loads(line) for line in jsonl_out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 5


def test_cli_quarantine_ruleset_and_error_exit_codes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rc = main(["quarantine", "--print-ruleset"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "table inet netguard" in captured.out
    assert "blocked_ipv4" in captured.out

    # Missing file -> non-zero exit code 1
    rc_missing = main(["analyze", str(tmp_path / "missing.pcap"), "--quiet"])
    assert rc_missing == 1

    # Invalid configuration value -> exit code 2
    rc_bad_cfg = main(["analyze", str(tmp_path / "missing.pcap"), "--window", "-5"])
    assert rc_bad_cfg == 2
