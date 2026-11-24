"""Automated Linux nftables IP quarantine manager with dry-run & safety guards."""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from .config import QuarantineConfig
from .models import SEVERITY_RANK, Alert, QuarantineRecord

IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address

_PROTECTED_V4_NETWORKS = (
    (ipaddress.ip_network("127.0.0.0/8"), "loopback"),
    (ipaddress.ip_network("0.0.0.0/32"), "unspecified"),
    (ipaddress.ip_network("169.254.0.0/16"), "link-local"),
    (ipaddress.ip_network("224.0.0.0/4"), "multicast"),
    (ipaddress.ip_network("255.255.255.255/32"), "broadcast"),
)

_PROTECTED_V6_NETWORKS = (
    (ipaddress.ip_network("::1/128"), "loopback"),
    (ipaddress.ip_network("::/128"), "unspecified"),
    (ipaddress.ip_network("fe80::/10"), "link-local"),
    (ipaddress.ip_network("ff00::/8"), "multicast"),
)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class NftablesQuarantineManager:
    """Manages automated IP quarantine rules via Linux nftables inet tables."""

    def __init__(self, config: QuarantineConfig | None = None) -> None:
        self.config = config or QuarantineConfig()
        self._allowlist_nets = [
            ipaddress.ip_network(cidr, strict=False) for cidr in self.config.allowlist_cidrs
        ]
        self._active_blocks: dict[str, QuarantineRecord] = {}
        self._records: list[QuarantineRecord] = []
        self._bootstrapped = False

    def reset(self) -> None:
        self._active_blocks.clear()
        self._records.clear()
        self._bootstrapped = False

    @property
    def records(self) -> list[QuarantineRecord]:
        return list(self._records)

    @staticmethod
    def validate_ip(ip_str: str | None) -> IPAddr | None:
        """Strictly parse an IPv4/IPv6 literal; reject malformed strings or injection."""
        if not ip_str or not isinstance(ip_str, str):
            return None
        if any(ch.isspace() or ch in ";|&$`{}[]" for ch in ip_str):
            return None
        try:
            return ipaddress.ip_address(ip_str)
        except ValueError:
            return None

    def is_protected(self, ip_obj: IPAddr) -> tuple[bool, str]:
        """Check whether an IP falls under built-in safety nets or user allowlist."""
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for net, label in _PROTECTED_V4_NETWORKS:
                if ip_obj in net:
                    return True, f"built-in protected {label} range ({net})"
        else:
            for net, label in _PROTECTED_V6_NETWORKS:
                if ip_obj in net:
                    return True, f"built-in protected {label} range ({net})"

        for net in self._allowlist_nets:
            if ip_obj.version == net.version and ip_obj in net:
                return True, f"user allowlist CIDR ({net})"

        return False, ""

    def generate_bootstrap_ruleset(self) -> str:
        """Render the declarative nftables inet table, timeout sets, and input drop chain."""
        table = self.config.table_name
        return (
            f"table inet {table} {{\n"
            f"    set blocked_ipv4 {{\n"
            f"        type ipv4_addr\n"
            f"        flags timeout\n"
            f"    }}\n\n"
            f"    set blocked_ipv6 {{\n"
            f"        type ipv6_addr\n"
            f"        flags timeout\n"
            f"    }}\n\n"
            f"    chain quarantine_input {{\n"
            f"        type filter hook input priority filter; policy accept;\n"
            f"        ip saddr @blocked_ipv4 counter drop\n"
            f"        ip6 saddr @blocked_ipv6 counter drop\n"
            f"    }}\n"
            f"}}\n"
        )

    def _set_name_for(self, ip_obj: IPAddr) -> str:
        return "blocked_ipv4" if ip_obj.version == 4 else "blocked_ipv6"

    def build_block_commands(self, ip_obj: IPAddr) -> list[list[str]]:
        """Return safe argv command lists to initialize sets and block one IP with timeout."""
        table = self.config.table_name
        set_name = self._set_name_for(ip_obj)
        ip_type = "ipv4_addr" if ip_obj.version == 4 else "ipv6_addr"
        timeout = f"{self.config.timeout_seconds}s"
        return [
            ["nft", "add", "table", "inet", table],
            ["nft", "add", "set", "inet", table, set_name, "{", "type", ip_type, ";", "flags", "timeout", ";", "}"],
            [
                "nft",
                "add",
                "chain",
                "inet",
                table,
                "quarantine_input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            [
                "nft",
                "add",
                "element",
                "inet",
                table,
                set_name,
                "{",
                str(ip_obj),
                "timeout",
                timeout,
                "}",
            ],
        ]

    def _run_nft(self, cmd: list[str]) -> tuple[bool, str]:
        """Execute a single nft argv command safely without shell=True."""
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except OSError as exc:
            return False, str(exc)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
            return False, err
        return True, (proc.stdout or "").strip()

    def _ensure_live_bootstrap(self) -> tuple[bool, str]:
        """Ensure the nftables table, sets, and input hook rule exist before adding elements."""
        if self._bootstrapped:
            return True, ""
        ruleset = self.generate_bootstrap_ruleset()
        try:
            proc = subprocess.run(
                ["nft", "-f", "-"],
                input=ruleset,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            return False, str(exc)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
            return False, err
        self._bootstrapped = True
        return True, ""

    def evaluate_alert(self, alert: Alert) -> QuarantineRecord | None:
        """Evaluate an alert against quarantine policy and execute/simulate block."""
        if not self.config.enabled:
            return None

        if SEVERITY_RANK.get(alert.severity, 0) < SEVERITY_RANK.get(self.config.min_severity, 3):
            return None

        ts = alert.timestamp or _utc_now()
        ip_obj = self.validate_ip(alert.src_ip)
        if ip_obj is None:
            record = QuarantineRecord(
                ip=str(alert.src_ip or ""),
                family="unknown",
                status="invalid_ip",
                reason="Missing or invalid source IP address",
                alert_id=alert.alert_id,
                timestamp=ts,
                timeout_seconds=self.config.timeout_seconds,
                commands=[],
                detail="Cannot quarantine alert without a valid IPv4/IPv6 source address",
            )
            self._records.append(record)
            alert.quarantine_action = "invalid_ip"
            alert.quarantine_detail = record.detail
            return record

        ip_norm = str(ip_obj)
        family = f"ipv{ip_obj.version}"

        protected, why = self.is_protected(ip_obj)
        if protected:
            record = QuarantineRecord(
                ip=ip_norm,
                family=family,
                status="skipped_allowlisted",
                reason=why,
                alert_id=alert.alert_id,
                timestamp=ts,
                timeout_seconds=self.config.timeout_seconds,
                commands=[],
                detail=f"Protected IP skipped by safety guard: {why}",
            )
            self._records.append(record)
            alert.quarantine_action = "skipped_allowlisted"
            alert.quarantine_detail = record.detail
            return record

        if ip_norm in self._active_blocks:
            action = "dry_run" if self.config.dry_run else "already_quarantined"
            alert.quarantine_action = action
            alert.quarantine_detail = f"{ip_norm} is already quarantined"
            return None

        cmds = self.build_block_commands(ip_obj)
        cmd_strings = [" ".join(c) for c in cmds]

        if self.config.dry_run:
            record = QuarantineRecord(
                ip=ip_norm,
                family=family,
                status="dry_run",
                reason=f"{alert.alert_type} ({alert.severity})",
                alert_id=alert.alert_id,
                timestamp=ts,
                timeout_seconds=self.config.timeout_seconds,
                commands=cmd_strings,
                detail=f"Dry-run: would drop {ip_norm} in inet {self.config.table_name} for {self.config.timeout_seconds}s",
            )
            self._active_blocks[ip_norm] = record
            self._records.append(record)
            alert.quarantine_action = "dry_run"
            alert.quarantine_detail = record.detail
            return record

        # Live execution mode
        if shutil.which("nft") is None:
            record = QuarantineRecord(
                ip=ip_norm,
                family=family,
                status="failed",
                reason=f"{alert.alert_type} ({alert.severity})",
                alert_id=alert.alert_id,
                timestamp=ts,
                timeout_seconds=self.config.timeout_seconds,
                commands=cmd_strings,
                detail="`nft` binary not found on PATH; install nftables or use dry-run mode",
            )
            self._records.append(record)
            alert.quarantine_action = "failed"
            alert.quarantine_detail = record.detail
            return record

        if os.geteuid() != 0:
            record = QuarantineRecord(
                ip=ip_norm,
                family=family,
                status="failed",
                reason=f"{alert.alert_type} ({alert.severity})",
                alert_id=alert.alert_id,
                timestamp=ts,
                timeout_seconds=self.config.timeout_seconds,
                commands=cmd_strings,
                detail="Live nftables quarantine requires root privileges (CAP_NET_ADMIN / sudo)",
            )
            self._records.append(record)
            alert.quarantine_action = "failed"
            alert.quarantine_detail = record.detail
            return record

        ok, detail = self._ensure_live_bootstrap()
        if ok:
            ok, detail = self._run_nft(cmds[-1])

        if ok:
            record = QuarantineRecord(
                ip=ip_norm,
                family=family,
                status="applied",
                reason=f"{alert.alert_type} ({alert.severity})",
                alert_id=alert.alert_id,
                timestamp=ts,
                timeout_seconds=self.config.timeout_seconds,
                commands=cmd_strings,
                detail=f"Blocked {ip_norm} in inet {self.config.table_name} for {self.config.timeout_seconds}s",
            )
            self._active_blocks[ip_norm] = record
            self._records.append(record)
            alert.quarantine_action = "applied"
            alert.quarantine_detail = record.detail
            return record

        record = QuarantineRecord(
            ip=ip_norm,
            family=family,
            status="failed",
            reason=f"{alert.alert_type} ({alert.severity})",
            alert_id=alert.alert_id,
            timestamp=ts,
            timeout_seconds=self.config.timeout_seconds,
            commands=cmd_strings,
            detail=f"nftables command failed: {detail}",
        )
        self._records.append(record)
        alert.quarantine_action = "failed"
        alert.quarantine_detail = record.detail
        return record

    def unblock_ip(self, ip_str: str) -> tuple[bool, str]:
        """Remove an IP address from the nftables quarantine set (or dry-run state)."""
        ip_obj = self.validate_ip(ip_str)
        if ip_obj is None:
            return False, f"Invalid IP address: {ip_str!r}"
        ip_norm = str(ip_obj)
        set_name = self._set_name_for(ip_obj)
        cmd = ["nft", "delete", "element", "inet", self.config.table_name, set_name, "{", ip_norm, "}"]

        if self.config.dry_run:
            self._active_blocks.pop(ip_norm, None)
            return True, f"Dry-run: {' '.join(cmd)}"

        if shutil.which("nft") is None:
            return False, "`nft` binary not found on PATH"
        if os.geteuid() != 0:
            return False, "Unblocking live nftables entries requires root privileges"
        ok, msg = self._run_nft(cmd)
        if ok:
            self._active_blocks.pop(ip_norm, None)
            return True, f"Removed {ip_norm} from {self.config.table_name}/{set_name}"
        return False, msg

    def list_active_blocks(self) -> tuple[bool, list[str] | str]:
        """Return active blocked IPs from dry-run cache or live `nft list table`."""
        if self.config.dry_run:
            return True, sorted(self._active_blocks.keys())
        if shutil.which("nft") is None:
            return False, "`nft` binary not found on PATH"
        if os.geteuid() != 0:
            return False, "Inspecting live nftables tables requires root privileges"
        ok, out = self._run_nft(["nft", "list", "table", "inet", self.config.table_name])
        return ok, out

    def flush_table(self) -> tuple[bool, str]:
        """Delete the entire NetGuard nftables table (clean rollback)."""
        cmd = ["nft", "delete", "table", "inet", self.config.table_name]
        if self.config.dry_run:
            self._active_blocks.clear()
            self._bootstrapped = False
            return True, f"Dry-run: {' '.join(cmd)}"
        if shutil.which("nft") is None:
            return False, "`nft` binary not found on PATH"
        if os.geteuid() != 0:
            return False, "Flushing live nftables tables requires root privileges"
        ok, msg = self._run_nft(cmd)
        if ok:
            self._active_blocks.clear()
            self._bootstrapped = False
            return True, f"Flushed nftables table inet {self.config.table_name}"
        return False, msg
