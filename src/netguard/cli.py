"""Rich-powered CLI for NetGuard packet anomaly & stealth recon detection."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .alert_io import append_jsonl_alert, write_json_report, write_jsonl_alerts
from .config import DetectorConfig, QuarantineConfig
from .engine import PacketAnalyzer, PcapReadError
from .models import Alert, AnalysisResult
from .quarantine import NftablesQuarantineManager
from .sample_generator import SAMPLE_CATALOG, generate_all_samples

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "cyan",
    "LOW": "green",
}


def _parse_static_arp(items: list[str] | None) -> dict[str, str]:
    mappings: dict[str, str] = {}
    if not items:
        return mappings
    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid --arp-static entry {item!r}; expected IP=MAC")
        ip_part, mac_part = item.split("=", 1)
        mappings[ip_part.strip()] = mac_part.strip()
    return mappings


def _build_configs(args: argparse.Namespace) -> tuple[DetectorConfig, QuarantineConfig]:
    arp_static = _parse_static_arp(getattr(args, "arp_static", None))
    det_cfg = DetectorConfig(
        scan_window_seconds=args.window,
        syn_scan_port_threshold=args.syn_threshold,
        stealth_scan_port_threshold=args.stealth_threshold,
        track_half_open_only=not getattr(args, "all_syn", False),
        alert_cooldown_seconds=args.cooldown,
        dns_entropy_threshold=args.dns_entropy,
        dns_max_subdomain_len=args.dns_max_len,
        dns_txt_length_threshold=args.dns_txt_len,
        dns_allowlist_domains=tuple(getattr(args, "dns_allowlist", None) or ()),
        arp_static_bindings=arp_static,
        arp_ignored_ips=tuple(getattr(args, "arp_ignore", None) or ()),
    )

    live_q = bool(getattr(args, "live_quarantine", False))
    dry_q = bool(getattr(args, "quarantine", False))
    q_cfg = QuarantineConfig(
        enabled=dry_q or live_q,
        dry_run=not live_q,
        timeout_seconds=args.quarantine_timeout,
        min_severity=args.quarantine_min_severity,
        table_name=args.nft_table,
        allowlist_cidrs=tuple(getattr(args, "allowlist", None) or ()),
    )
    return det_cfg, q_cfg


def _render_result(console: Console, result: AnalysisResult) -> None:
    sev = result.severity_counts
    summary_text = (
        f"[bold]Source:[/bold] {result.source}\n"
        f"[bold]Packets:[/bold] {result.total_packets}    "
        f"[bold]Duration:[/bold] {result.duration_ms:.2f} ms    "
        f"[bold]Alerts:[/bold] {len(result.alerts)} "
        f"([red]CRITICAL: {sev['CRITICAL']}[/red], "
        f"[yellow]HIGH: {sev['HIGH']}[/yellow], "
        f"[cyan]MEDIUM: {sev['MEDIUM']}[/cyan], "
        f"[green]LOW: {sev['LOW']}[/green])"
    )
    console.print(Panel(summary_text, title=f"NetGuard v{__version__} Analysis Summary", border_style="cyan"))

    if not result.alerts:
        console.print("[bold green]No security threats detected.[/bold green]")
    else:
        table = Table(title="Security Alerts", show_lines=False)
        table.add_column("ID", style="dim", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Type", style="bold")
        table.add_column("MITRE", no_wrap=True)
        table.add_column("Source -> Dest")
        table.add_column("Quarantine", no_wrap=True)
        table.add_column("Summary")

        for alert in result.alerts:
            style = _SEVERITY_COLORS.get(alert.severity, "white")
            src = alert.src_ip or alert.src_mac or "-"
            dst = alert.dst_ip or alert.dst_mac or "-"
            table.add_row(
                alert.alert_id,
                f"[{style}]{alert.severity}[/{style}]",
                alert.alert_type,
                alert.mitre_attack.technique_id,
                f"{src} -> {dst}",
                alert.quarantine_action,
                alert.summary,
            )
        console.print(table)

    if result.quarantine_records:
        q_table = Table(title="nftables Quarantine Actions")
        q_table.add_column("Alert ID", style="dim", no_wrap=True)
        q_table.add_column("IP", style="bold")
        q_table.add_column("Status")
        q_table.add_column("Detail")
        for rec in result.quarantine_records:
            q_table.add_row(rec.alert_id, rec.ip or "-", rec.status, rec.detail)
        console.print(q_table)


def _add_detector_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--window", type=float, default=10.0, help="Port scan sliding window in seconds (default: 10.0)")
    parser.add_argument("--syn-threshold", type=int, default=15, help="Unique ports for SYN scan alert (default: 15)")
    parser.add_argument("--stealth-threshold", type=int, default=5, help="Unique ports for FIN/NULL/Xmas alerts (default: 5)")
    parser.add_argument("--all-syn", action="store_true", help="Count all SYNs including completed handshakes")
    parser.add_argument("--cooldown", type=float, default=30.0, help="Alert cooldown in seconds (default: 30.0)")
    parser.add_argument("--dns-entropy", type=float, default=3.8, help="Shannon entropy threshold for DNS subdomains (default: 3.8)")
    parser.add_argument("--dns-max-len", type=int, default=50, help="Max normal DNS subdomain length (default: 50)")
    parser.add_argument("--dns-txt-len", type=int, default=45, help="TXT record suspicious length threshold (default: 45)")
    parser.add_argument("--dns-allowlist", action="append", help="Additional trusted base domain to exclude (repeatable)")
    parser.add_argument("--arp-static", action="append", help="Static trusted IP=MAC binding (repeatable)")
    parser.add_argument("--arp-ignore", action="append", help="IP to ignore in ARP conflict checks (repeatable)")
    parser.add_argument("--quarantine", action="store_true", help="Enable nftables quarantine in safe dry-run mode")
    parser.add_argument("--live-quarantine", action="store_true", help="Apply real nftables drops (requires root)")
    parser.add_argument("--quarantine-timeout", type=int, default=900, help="nftables auto-expire timeout in seconds (default: 900)")
    parser.add_argument("--quarantine-min-severity", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Minimum alert severity for quarantine (default: HIGH)")
    parser.add_argument("--nft-table", default="netguard", help="nftables inet table name (default: netguard)")
    parser.add_argument("--allowlist", action="append", help="CIDR/IP never to quarantine (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard: Python & Scapy Network Packet Anomaly & Stealth Recon Detector",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze an offline .pcap / .pcapng capture file")
    p_analyze.add_argument("pcap_path", help="Path to .pcap or .pcapng file")
    p_analyze.add_argument("--json", dest="json_out", help="Write full JSON report to path")
    p_analyze.add_argument("--jsonl", dest="jsonl_out", help="Write alerts as JSONL to path")
    p_analyze.add_argument("--quiet", action="store_true", help="Suppress rich terminal tables")
    _add_detector_flags(p_analyze)

    # live
    p_live = sub.add_parser("live", help="Sniff and analyze live traffic on a network interface")
    p_live.add_argument("-i", "--interface", required=True, help="Network interface (e.g. eth0, lo, wlan0)")
    p_live.add_argument("--filter", dest="bpf_filter", default=None, help="Optional BPF capture filter")
    p_live.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = unlimited)")
    p_live.add_argument("--timeout", type=float, default=None, help="Stop after N seconds")
    p_live.add_argument("--json", dest="json_out", help="Write final JSON report on exit")
    p_live.add_argument("--jsonl", dest="jsonl_out", help="Stream each alert as JSONL to path")
    p_live.add_argument("--quiet", action="store_true", help="Suppress live console output")
    _add_detector_flags(p_live)

    # generate-samples
    p_gen = sub.add_parser("generate-samples", help="Generate deterministic demonstration .pcap files")
    p_gen.add_argument("--output-dir", default="samples", help="Directory to write sample .pcap files (default: samples)")

    # quarantine
    p_quar = sub.add_parser("quarantine", help="Inspect or manage NetGuard nftables quarantine state")
    group = p_quar.add_mutually_exclusive_group(required=True)
    group.add_argument("--print-ruleset", action="store_true", help="Print declarative nftables ruleset")
    group.add_argument("--list", action="store_true", help="List active quarantined IPs")
    group.add_argument("--unblock", metavar="IP", help="Remove an IP from the quarantine set")
    group.add_argument("--flush", action="store_true", help="Delete the NetGuard nftables table")
    p_quar.add_argument("--table", default="netguard", help="nftables inet table name (default: netguard)")
    p_quar.add_argument("--timeout", type=int, default=900, help="Default timeout seconds (default: 900)")
    p_quar.add_argument("--live", action="store_true", help="Target live kernel nftables (default is dry-run)")

    # web
    p_web = sub.add_parser("web", help="Launch the interactive NetGuard SOC Web Dashboard")
    p_web.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p_web.add_argument("--port", type=int, default=8080, help="Listen port (default: 8080)")
    p_web.add_argument("--samples-dir", default=None, help="Custom directory containing sample .pcap files")
    p_web.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    console = Console()
    err_console = Console(stderr=True)

    if args.command == "generate-samples":
        paths = generate_all_samples(args.output_dir)
        console.print(f"[bold green]Generated {len(paths)} sample PCAPs in {Path(args.output_dir).resolve()}:[/bold green]")
        for meta, path in zip(SAMPLE_CATALOG, paths):
            size_kb = path.stat().st_size / 1024.0
            console.print(f"  - [cyan]{path.name}[/cyan] ({size_kb:.1f} KB) — {meta.title}")
        return 0

    if args.command == "quarantine":
        try:
            q_cfg = QuarantineConfig(
                enabled=True,
                dry_run=not args.live,
                table_name=args.table,
                timeout_seconds=args.timeout,
            )
        except ValueError as exc:
            err_console.print(f"[red]Configuration error:[/red] {exc}")
            return 2
        mgr = NftablesQuarantineManager(q_cfg)
        if args.print_ruleset:
            sys.stdout.write(mgr.generate_bootstrap_ruleset())
            return 0
        if args.list:
            ok, out = mgr.list_active_blocks()
            if not ok:
                err_console.print(f"[red]Error:[/red] {out}")
                return 1
            console.print(out)
            return 0
        if args.unblock:
            ok, msg = mgr.unblock_ip(args.unblock)
            if not ok:
                err_console.print(f"[red]Error:[/red] {msg}")
                return 1
            console.print(f"[green]{msg}[/green]")
            return 0
        if args.flush:
            ok, msg = mgr.flush_table()
            if not ok:
                err_console.print(f"[red]Error:[/red] {msg}")
                return 1
            console.print(f"[green]{msg}[/green]")
            return 0

    if args.command == "web":
        from .web.app import create_app

        samples_dir = Path(args.samples_dir) if args.samples_dir else None
        app = create_app(samples_dir=samples_dir)
        console.print(f"[bold cyan]Starting NetGuard SOC Dashboard[/bold cyan] at http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)
        return 0

    # analyze / live
    try:
        det_cfg, q_cfg = _build_configs(args)
    except ValueError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        return 2

    analyzer = PacketAnalyzer(detector_config=det_cfg, quarantine_config=q_cfg)

    if args.command == "analyze":
        try:
            result = analyzer.analyze_pcap(args.pcap_path)
        except PcapReadError as exc:
            err_console.print(f"[red]PCAP error:[/red] {exc}")
            return 1

        if args.json_out:
            write_json_report(result, args.json_out)
        if args.jsonl_out:
            write_jsonl_alerts(result.alerts, args.jsonl_out)

        if not args.quiet:
            _render_result(console, result)
        return 0

    if args.command == "live":
        stop_event = threading.Event()

        def _handle_signal(_signum: int, _frame: object) -> None:
            stop_event.set()

        old_int = signal.signal(signal.SIGINT, _handle_signal)
        old_term = signal.signal(signal.SIGTERM, _handle_signal)

        def _on_live_alert(alert: Alert) -> None:
            if args.jsonl_out:
                append_jsonl_alert(alert, args.jsonl_out)
            if not args.quiet:
                style = _SEVERITY_COLORS.get(alert.severity, "white")
                console.print(
                    f"[{style}][{alert.severity}][/{style}] {alert.alert_type} | "
                    f"{alert.src_ip or alert.src_mac} -> {alert.dst_ip or '-'} | "
                    f"quarantine={alert.quarantine_action} | {alert.summary}"
                )

        if not args.quiet:
            console.print(
                f"[cyan]Listening on {args.interface}[/cyan] (Ctrl+C to stop) "
                f"| euid={os.geteuid()} | quarantine={'live' if not q_cfg.dry_run else ('dry-run' if q_cfg.enabled else 'off')}"
            )
        try:
            result = analyzer.sniff_live(
                interface=args.interface,
                bpf_filter=args.bpf_filter,
                packet_count=args.count,
                timeout=args.timeout,
                on_alert=_on_live_alert,
                stop_event=stop_event,
            )
        except (PermissionError, RuntimeError) as exc:
            err_console.print(f"[red]Live capture error:[/red] {exc}")
            return 1
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)

        if args.json_out:
            write_json_report(result, args.json_out)
        if not args.quiet:
            _render_result(console, result)
        return 0

    return 1
