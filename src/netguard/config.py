"""Configuration models and strict validation for NetGuard."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any

VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _normalize_mac(mac: str) -> str:
    """Validate and normalize a MAC address to lowercase colon-delimited form."""
    if not isinstance(mac, str) or not _MAC_RE.match(mac.strip()):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return mac.strip().replace("-", ":").lower()


def _validate_finite_float(value: Any, name: str, *, min_val: float | None = None, exclusive_min: bool = False) -> float:
    """Coerce and validate a finite numeric float parameter."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number, got bool")
    try:
        num = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a valid number, got {value!r}") from exc
    if not math.isfinite(num):
        raise ValueError(f"{name} must be finite, got {value!r}")
    if min_val is not None:
        if exclusive_min and num <= min_val:
            raise ValueError(f"{name} must be > {min_val}, got {num}")
        if not exclusive_min and num < min_val:
            raise ValueError(f"{name} must be >= {min_val}, got {num}")
    return num


def _validate_int(value: Any, name: str, *, min_val: int = 1) -> int:
    """Coerce and validate an integer parameter."""
    if isinstance(value, bool) or isinstance(value, float):
        if isinstance(value, float) and not value.is_integer():
            raise ValueError(f"{name} must be an integer, got {value!r}")
        if isinstance(value, bool):
            raise ValueError(f"{name} must be an integer, got bool")
    try:
        num = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc
    if num < min_val:
        raise ValueError(f"{name} must be >= {min_val}, got {num}")
    return num


def _coerce_str_tuple(value: Any, name: str, *, lower: bool = True) -> tuple[str, ...]:
    """Coerce an iterable of strings into a normalized tuple."""
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, (list, tuple, set)):
        items = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"All items in {name} must be strings, got {type(item).__name__}")
            cleaned = item.strip()
            if cleaned:
                items.append(cleaned)
    else:
        raise ValueError(f"{name} must be a list/tuple of strings or comma-separated string")
    return tuple(item.lower() if lower else item for item in items)


@dataclass
class DetectorConfig:
    """Thresholds, window settings, and allowlists for packet anomaly detectors."""

    # Port scan detection
    scan_window_seconds: float = 10.0
    syn_scan_port_threshold: int = 15
    stealth_scan_port_threshold: int = 5
    track_half_open_only: bool = True
    alert_cooldown_seconds: float = 30.0

    # DNS tunneling detection
    dns_entropy_threshold: float = 3.8
    dns_min_subdomain_len: int = 20
    dns_max_subdomain_len: int = 50
    dns_max_fqdn_len: int = 120
    dns_txt_length_threshold: int = 45
    dns_allowlist_suffixes: tuple[str, ...] = ("in-addr.arpa", "ip6.arpa", "local")
    dns_ignore_prefixes: tuple[str, ...] = ("_dmarc.", "_domainkey.", "_spf.", "_acme-challenge.")
    dns_allowlist_domains: tuple[str, ...] = ()

    # ARP spoofing detection
    arp_check_header_mismatch: bool = True
    arp_static_bindings: dict[str, str] = field(default_factory=dict)
    arp_ignored_ips: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.scan_window_seconds = _validate_finite_float(
            self.scan_window_seconds, "scan_window_seconds", min_val=0.0, exclusive_min=True
        )
        self.syn_scan_port_threshold = _validate_int(
            self.syn_scan_port_threshold, "syn_scan_port_threshold", min_val=1
        )
        self.stealth_scan_port_threshold = _validate_int(
            self.stealth_scan_port_threshold, "stealth_scan_port_threshold", min_val=1
        )
        if not isinstance(self.track_half_open_only, bool):
            raise ValueError("track_half_open_only must be a boolean")
        self.alert_cooldown_seconds = _validate_finite_float(
            self.alert_cooldown_seconds, "alert_cooldown_seconds", min_val=0.0, exclusive_min=False
        )

        self.dns_entropy_threshold = _validate_finite_float(
            self.dns_entropy_threshold, "dns_entropy_threshold", min_val=0.0, exclusive_min=True
        )
        self.dns_min_subdomain_len = _validate_int(
            self.dns_min_subdomain_len, "dns_min_subdomain_len", min_val=1
        )
        self.dns_max_subdomain_len = _validate_int(
            self.dns_max_subdomain_len, "dns_max_subdomain_len", min_val=1
        )
        self.dns_max_fqdn_len = _validate_int(
            self.dns_max_fqdn_len, "dns_max_fqdn_len", min_val=1
        )
        self.dns_txt_length_threshold = _validate_int(
            self.dns_txt_length_threshold, "dns_txt_length_threshold", min_val=1
        )

        self.dns_allowlist_suffixes = tuple(
            s.lstrip(".") for s in _coerce_str_tuple(self.dns_allowlist_suffixes, "dns_allowlist_suffixes")
        )
        self.dns_ignore_prefixes = _coerce_str_tuple(self.dns_ignore_prefixes, "dns_ignore_prefixes")
        self.dns_allowlist_domains = tuple(
            s.strip(".") for s in _coerce_str_tuple(self.dns_allowlist_domains, "dns_allowlist_domains")
        )

        if not isinstance(self.arp_check_header_mismatch, bool):
            raise ValueError("arp_check_header_mismatch must be a boolean")

        if not isinstance(self.arp_static_bindings, dict):
            raise ValueError("arp_static_bindings must be a dict mapping IP -> MAC")
        normalized_bindings: dict[str, str] = {}
        for ip_str, mac_str in self.arp_static_bindings.items():
            try:
                validated_ip = str(ipaddress.ip_address(str(ip_str).strip()))
            except ValueError as exc:
                raise ValueError(f"Invalid IP in arp_static_bindings: {ip_str!r}") from exc
            normalized_bindings[validated_ip] = _normalize_mac(mac_str)
        self.arp_static_bindings = normalized_bindings

        raw_ignored = _coerce_str_tuple(self.arp_ignored_ips, "arp_ignored_ips", lower=False)
        validated_ignored: list[str] = []
        for ip_str in raw_ignored:
            try:
                validated_ignored.append(str(ipaddress.ip_address(ip_str)))
            except ValueError as exc:
                raise ValueError(f"Invalid IP in arp_ignored_ips: {ip_str!r}") from exc
        self.arp_ignored_ips = tuple(validated_ignored)

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration to a JSON-friendly dictionary."""
        data = asdict(self)
        data["dns_allowlist_suffixes"] = list(self.dns_allowlist_suffixes)
        data["dns_ignore_prefixes"] = list(self.dns_ignore_prefixes)
        data["dns_allowlist_domains"] = list(self.dns_allowlist_domains)
        data["arp_ignored_ips"] = list(self.arp_ignored_ips)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> DetectorConfig:
        """Create a validated DetectorConfig from a partial or full dictionary."""
        if not data:
            return cls()
        if not isinstance(data, dict):
            raise ValueError("detector_config must be a JSON object")
        valid_keys = set(cls.__dataclass_fields__.keys())
        unknown = set(data.keys()) - valid_keys
        if unknown:
            raise ValueError(f"Unknown DetectorConfig keys: {sorted(unknown)}")
        return cls(**data)


@dataclass
class QuarantineConfig:
    """Configuration for automated nftables IP quarantine actions."""

    enabled: bool = False
    dry_run: bool = True
    timeout_seconds: int = 900
    min_severity: str = "HIGH"
    table_name: str = "netguard"
    allowlist_cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a boolean")
        if not isinstance(self.dry_run, bool):
            raise ValueError("dry_run must be a boolean")
        self.timeout_seconds = _validate_int(self.timeout_seconds, "timeout_seconds", min_val=1)

        if not isinstance(self.min_severity, str):
            raise ValueError("min_severity must be a string")
        sev = self.min_severity.strip().upper()
        if sev not in VALID_SEVERITIES:
            raise ValueError(f"min_severity must be one of {VALID_SEVERITIES}, got {self.min_severity!r}")
        self.min_severity = sev

        if not isinstance(self.table_name, str) or not _TABLE_NAME_RE.match(self.table_name):
            raise ValueError(
                f"table_name must match ^[A-Za-z_][A-Za-z0-9_]{{0,63}}$, got {self.table_name!r}"
            )

        raw_cidrs = _coerce_str_tuple(self.allowlist_cidrs, "allowlist_cidrs", lower=False)
        normalized_cidrs: list[str] = []
        for cidr in raw_cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR in allowlist_cidrs: {cidr!r}") from exc
            normalized_cidrs.append(str(net))
        self.allowlist_cidrs = tuple(normalized_cidrs)

    def to_dict(self) -> dict[str, Any]:
        """Serialize quarantine configuration to a JSON-friendly dictionary."""
        data = asdict(self)
        data["allowlist_cidrs"] = list(self.allowlist_cidrs)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> QuarantineConfig:
        """Create a validated QuarantineConfig from a partial or full dictionary."""
        if not data:
            return cls()
        if not isinstance(data, dict):
            raise ValueError("quarantine_config must be a JSON object")
        valid_keys = set(cls.__dataclass_fields__.keys())
        unknown = set(data.keys()) - valid_keys
        if unknown:
            raise ValueError(f"Unknown QuarantineConfig keys: {sorted(unknown)}")
        return cls(**data)
