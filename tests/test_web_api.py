"""Flask SOC Web Dashboard REST API and upload edge-case tests."""

from __future__ import annotations

import io
from pathlib import Path

from netguard.web.app import create_app


def test_web_routes_and_sample_analysis(generated_samples_dir: Path) -> None:
    app = create_app(samples_dir=generated_samples_dir)
    client = app.test_client()

    # Dashboard HTML, static assets, & health
    home = client.get("/")
    assert home.status_code == 200
    assert b"NetGuard SOC" in home.data
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"

    # Config defaults & samples list
    defaults = client.get("/api/config/defaults").get_json()
    assert "detector" in defaults and "quarantine" in defaults

    samples = client.get("/api/samples").get_json()["samples"]
    assert len(samples) == 6
    assert all(s["exists"] for s in samples)

    # Analyze full killchain sample (also verify web enforces dry_run=True)
    resp = client.post(
        "/api/analyze/sample",
        json={
            "sample_id": "04_full_killchain_demo",
            "quarantine_config": {"enabled": True, "dry_run": False},
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["alert_count"] == 5
    assert data["config"]["quarantine"]["dry_run"] is True

    # Analyze benign baseline -> 0 alerts
    benign = client.post("/api/analyze/sample", json={"sample_id": "05_benign_baseline"}).get_json()
    assert benign["alert_count"] == 0

    # Path traversal / unknown sample ID rejected
    bad_sample = client.post("/api/analyze/sample", json={"sample_id": "../../etc/passwd"})
    assert bad_sample.status_code == 400


def test_web_upload_quarantine_preview_and_architecture(generated_samples_dir: Path) -> None:
    app = create_app(samples_dir=generated_samples_dir)
    client = app.test_client()

    # Valid upload
    pcap_bytes = (generated_samples_dir / "03_arp_spoofing.pcap").read_bytes()
    up_ok = client.post(
        "/api/analyze/upload",
        data={
            "file": (io.BytesIO(pcap_bytes), "arp_test.pcap"),
            "quarantine_config": '{"enabled": true}',
        },
        content_type="multipart/form-data",
    )
    assert up_ok.status_code == 200
    up_json = up_ok.get_json()
    assert up_json["source"] == "arp_test.pcap"
    assert up_json["alert_count"] == 2

    # Empty 0-byte upload -> 400
    up_empty = client.post(
        "/api/analyze/upload",
        data={"file": (io.BytesIO(b""), "empty.pcap")},
        content_type="multipart/form-data",
    )
    assert up_empty.status_code == 400

    # Corrupted non-PCAP upload -> 400
    up_bad = client.post(
        "/api/analyze/upload",
        data={"file": (io.BytesIO(b"corrupted-garbage-bytes"), "bad.pcap")},
        content_type="multipart/form-data",
    )
    assert up_bad.status_code == 400

    # Bad JSON config -> 400
    up_bad_cfg = client.post(
        "/api/analyze/upload",
        data={"file": (io.BytesIO(pcap_bytes), "arp.pcap"), "detector_config": "{invalid"},
        content_type="multipart/form-data",
    )
    assert up_bad_cfg.status_code == 400

    # Quarantine preview & architecture endpoint
    q_prev = client.post(
        "/api/quarantine/preview",
        json={"ips": ["203.0.113.45", "127.0.0.1", "192.168.10.1"], "allowlist_cidrs": ["192.168.10.1/32"]},
    )
    assert q_prev.status_code == 200
    evals = {e["ip"]: e["status"] for e in q_prev.get_json()["evaluations"]}
    assert evals == {
        "203.0.113.45": "dry_run",
        "127.0.0.1": "skipped_allowlisted",
        "192.168.10.1": "skipped_allowlisted",
    }

    arch = client.get("/api/docs/architecture")
    assert arch.status_code == 200
    assert len(arch.get_json()["mitre_coverage"]) >= 4
