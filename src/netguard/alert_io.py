"""Structured JSON and JSONL alert serialization utilities."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Alert, AnalysisResult


def write_json_report(result: AnalysisResult, path: str | Path) -> Path:
    """Write a complete AnalysisResult report as pretty-printed JSON."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)
        fh.write("\n")
    return out_path


def write_jsonl_alerts(alerts: list[Alert], path: str | Path) -> Path:
    """Write a sequence of alerts as newline-delimited JSON (JSONL)."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert.to_dict(), separators=(",", ":")))
            fh.write("\n")
    return out_path


def append_jsonl_alert(alert: Alert, path: str | Path) -> Path:
    """Append a single alert to a JSONL log file (used during live capture)."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(alert.to_dict(), separators=(",", ":")))
        fh.write("\n")
    return out_path
