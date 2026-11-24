"""Flask backend API and dashboard routes for the NetGuard SOC interface."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from .. import __version__
from ..config import DetectorConfig, QuarantineConfig
from ..engine import PacketAnalyzer, PcapReadError
from ..models import Alert, MitreMapping
from ..quarantine import NftablesQuarantineManager
from ..sample_generator import SAMPLE_CATALOG

_DEFAULT_SAMPLES_DIR = Path(__file__).resolve().parents[3] / "samples"
_SAMPLE_BY_ID = {item.sample_id: item for item in SAMPLE_CATALOG}


def _parse_configs(
    raw_detector: Any, raw_quarantine: Any
) -> tuple[DetectorConfig, QuarantineConfig]:
    det_cfg = DetectorConfig.from_dict(raw_detector)
    q_dict = dict(raw_quarantine) if isinstance(raw_quarantine, dict) else {}
    if raw_quarantine is not None and not isinstance(raw_quarantine, dict):
        raise ValueError("quarantine_config must be a JSON object")

    # Web UI enforces safe dry-run unless server operator explicitly opts into live nft
    if os.environ.get("NETGUARD_WEB_ALLOW_LIVE_NFT") != "1":
        q_dict["dry_run"] = True

    q_cfg = QuarantineConfig.from_dict(q_dict)
    return det_cfg, q_cfg


def create_app(samples_dir: str | Path | None = None) -> Flask:
    """Create and configure the NetGuard Flask SOC Dashboard application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload limit
    resolved_samples = Path(samples_dir) if samples_dir is not None else _DEFAULT_SAMPLES_DIR
    if not resolved_samples.exists() and (Path.cwd() / "samples").exists():
        resolved_samples = Path.cwd() / "samples"
    app.config["SAMPLES_DIR"] = resolved_samples

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_err: RequestEntityTooLarge) -> tuple[Any, int]:
        return jsonify({"error": "Uploaded capture file exceeds the 25 MB limit."}), 413

    @app.get("/")
    def index() -> str:
        return render_template("index.html", version=__version__)

    @app.get("/api/health")
    def health() -> Any:
        return jsonify({"status": "ok", "version": __version__})

    @app.get("/api/config/defaults")
    def config_defaults() -> Any:
        return jsonify({
            "detector": DetectorConfig().to_dict(),
            "quarantine": QuarantineConfig().to_dict(),
        })

    @app.get("/api/samples")
    def list_samples() -> Any:
        s_dir = Path(app.config["SAMPLES_DIR"])
        items = []
        for meta in SAMPLE_CATALOG:
            file_path = s_dir / meta.filename
            exists = file_path.is_file()
            size_bytes = file_path.stat().st_size if exists else 0
            entry = meta.to_dict()
            entry["exists"] = exists
            entry["size_bytes"] = size_bytes
            items.append(entry)
        return jsonify({"samples": items})

    @app.post("/api/analyze/sample")
    def analyze_sample() -> tuple[Any, int] | Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be valid JSON."}), 400

        sample_id = payload.get("sample_id")
        if not isinstance(sample_id, str) or sample_id not in _SAMPLE_BY_ID:
            return jsonify({"error": f"Unknown sample_id: {sample_id!r}"}), 400

        meta = _SAMPLE_BY_ID[sample_id]
        sample_path = Path(app.config["SAMPLES_DIR"]) / meta.filename
        if not sample_path.is_file():
            return jsonify({"error": f"Sample file '{meta.filename}' not found on disk."}), 404

        try:
            det_cfg, q_cfg = _parse_configs(
                payload.get("detector_config"),
                payload.get("quarantine_config"),
            )
            analyzer = PacketAnalyzer(detector_config=det_cfg, quarantine_config=q_cfg)
            result = analyzer.analyze_pcap(sample_path)
        except (ValueError, PcapReadError) as exc:
            return jsonify({"error": str(exc)}), 400

        out = result.to_dict()
        out["source"] = meta.filename
        out["sample_meta"] = meta.to_dict()
        return jsonify(out)

    @app.post("/api/analyze/upload")
    def analyze_upload() -> tuple[Any, int] | Any:
        if "file" not in request.files:
            return jsonify({"error": "No capture file provided under form field 'file'."}), 400

        upload = request.files["file"]
        raw_name = upload.filename or ""
        safe_name = secure_filename(raw_name)
        if not safe_name:
            return jsonify({"error": "Uploaded file must have a valid filename."}), 400

        data = upload.read()
        if not data:
            return jsonify({"error": "Uploaded capture file is empty (0 bytes)."}), 400

        raw_det = request.form.get("detector_config")
        raw_q = request.form.get("quarantine_config")
        try:
            det_dict = json.loads(raw_det) if raw_det else None
            q_dict = json.loads(raw_q) if raw_q else None
            det_cfg, q_cfg = _parse_configs(det_dict, q_dict)
        except (json.JSONDecodeError, ValueError) as exc:
            return jsonify({"error": f"Invalid configuration JSON: {exc}"}), 400

        tmp_path: Path | None = None
        try:
            suffix = ".pcapng" if safe_name.lower().endswith(".pcapng") else ".pcap"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)

            analyzer = PacketAnalyzer(detector_config=det_cfg, quarantine_config=q_cfg)
            result = analyzer.analyze_pcap(tmp_path)
        except PcapReadError as exc:
            return jsonify({"error": str(exc)}), 400
        finally:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

        out = result.to_dict()
        out["source"] = safe_name
        return jsonify(out)

    @app.post("/api/quarantine/preview")
    def quarantine_preview() -> tuple[Any, int] | Any:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be valid JSON."}), 400

        ips = payload.get("ips") or []
        if not isinstance(ips, list):
            return jsonify({"error": "'ips' must be a list of IP strings."}), 400

        try:
            q_cfg = QuarantineConfig.from_dict({
                "enabled": True,
                "dry_run": True,
                "timeout_seconds": payload.get("timeout_seconds", 900),
                "min_severity": payload.get("min_severity", "HIGH"),
                "table_name": payload.get("table_name", "netguard"),
                "allowlist_cidrs": payload.get("allowlist_cidrs", []),
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        mgr = NftablesQuarantineManager(q_cfg)
        evaluations = []
        for idx, raw_ip in enumerate(ips[:50], start=1):
            synthetic_alert = Alert(
                alert_id=f"PREVIEW-{idx:03d}",
                timestamp="preview",
                packet_timestamp=0.0,
                detector="preview",
                alert_type="SIMULATED_THREAT",
                severity="CRITICAL",
                mitre_attack=MitreMapping("Discovery", "T1046", "Network Service Discovery"),
                src_ip=str(raw_ip) if raw_ip is not None else "",
                dst_ip=None,
                src_mac=None,
                dst_mac=None,
                summary="Quarantine policy preview",
            )
            rec = mgr.evaluate_alert(synthetic_alert)
            if rec is not None:
                evaluations.append(rec.to_dict())

        return jsonify({
            "table_name": q_cfg.table_name,
            "timeout_seconds": q_cfg.timeout_seconds,
            "allowlist_cidrs": list(q_cfg.allowlist_cidrs),
            "bootstrap_ruleset": mgr.generate_bootstrap_ruleset(),
            "evaluations": evaluations,
        })

    @app.get("/api/docs/architecture")
    def architecture_docs() -> Any:
        return jsonify({
            "pipeline": [
                {
                    "stage": "1. Packet Ingestion",
                    "component": "PacketAnalyzer (engine.py)",
                    "details": "Streams .pcap/.pcapng via Scapy PcapReader or live interfaces via sniff(store=False), classifying L2-L7 protocols and packet timestamps.",
                },
                {
                    "stage": "2. Stateful Protocol Detectors",
                    "component": "PortScanDetector / DnsTunnelDetector / ArpSpoofDetector",
                    "details": "Detects half-open SYN & stealth FIN/NULL/Xmas scans (RFC 3168 ECN-masked), Shannon-entropy & oversized TXT DNS tunnels, and ARP IP-to-MAC poisoning.",
                },
                {
                    "stage": "3. Structured Alerting & Telemetry",
                    "component": "Alert & AnalysisResult (models.py, alert_io.py)",
                    "details": "Generates MITRE ATT&CK enriched JSON/JSONL alerts, ARP binding tables, DNS entropy scatter metrics, and targeted port histograms.",
                },
                {
                    "stage": "4. Automated Quarantine & SOC UI",
                    "component": "NftablesQuarantineManager & Flask Dashboard",
                    "details": "Evaluates severity & CIDR/loopback allowlists before emitting timeout-scoped Linux nftables drop rules (safe dry-run by default).",
                },
            ],
            "mitre_coverage": [
                {
                    "alert_type": "TCP_SYN_SCAN / TCP_FIN_SCAN / TCP_NULL_SCAN / TCP_XMAS_SCAN",
                    "tactic": "Discovery",
                    "technique": "T1046 — Network Service Discovery",
                    "severity": "HIGH / CRITICAL",
                },
                {
                    "alert_type": "DNS_HIGH_ENTROPY / DNS_LONG_SUBDOMAIN",
                    "tactic": "Command and Control",
                    "technique": "T1071.004 — Application Layer Protocol: DNS",
                    "severity": "MEDIUM / HIGH",
                },
                {
                    "alert_type": "DNS_TXT_TUNNELING",
                    "tactic": "Exfiltration",
                    "technique": "T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol",
                    "severity": "CRITICAL",
                },
                {
                    "alert_type": "ARP_IP_MAC_CONFLICT / ARP_HEADER_MISMATCH",
                    "tactic": "Credential Access",
                    "technique": "T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning",
                    "severity": "HIGH / CRITICAL",
                },
            ],
        })

    return app
