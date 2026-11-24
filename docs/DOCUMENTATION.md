# NetGuard Complete Documentation Guide

## Table of Contents
1. [Installation & Environment Setup](#1-installation--environment-setup)
2. [Permissions for Live Packet Capture & nftables](#2-permissions-for-live-packet-capture--nftables)
3. [Detection Engine Deep Dive](#3-detection-engine-deep-dive)
4. [CLI Reference](#4-cli-reference)
5. [SOC Web Dashboard Walkthrough](#5-soc-web-dashboard-walkthrough)
6. [Automated nftables Quarantine & Rollback](#6-automated-nftables-quarantine--rollback)
7. [False-Positive Tuning Playbook](#7-false-positive-tuning-playbook)
8. [Edge-Case Testing Matrix](#8-edge-case-testing-matrix)
9. [Troubleshooting FAQ](#9-troubleshooting-faq)

---

## 1. Installation & Environment Setup

NetGuard requires **Python 3.10+** and runs inside an isolated virtual environment (`.venv`).

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip setuptools
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e . --no-build-isolation
```

Verify installation:

```bash
.venv/bin/netguard --version
.venv/bin/pytest -v
```

### Project Layout

```text
Packet-Anomaly-Stealth-Recon-Detector/
├── pyproject.toml                  # Package metadata & `netguard` CLI entry point
├── requirements.txt                # Pinned runtime & test dependencies
├── src/netguard/
│   ├── config.py                   # Strict validated DetectorConfig & QuarantineConfig
│   ├── models.py                   # Alert, MitreMapping, ArpBinding, AnalysisResult models
│   ├── alert_io.py                 # JSON & JSONL report writers
│   ├── engine.py                   # PacketAnalyzer (PCAP streaming & live sniffing)
│   ├── quarantine.py               # Safe nftables manager (dry-run, allowlists, live drop)
│   ├── sample_generator.py         # Deterministic 6-file sample PCAP suite
│   ├── cli.py                      # Rich CLI (`analyze`, `live`, `web`, `quarantine`, ...)
│   ├── detectors/
│   │   ├── base.py                 # BaseDetector & IP/MAC/UTC timestamp helpers
│   │   ├── port_scan.py            # Half-open SYN & stealth FIN/NULL/Xmas detector
│   │   ├── dns_tunnel.py           # Shannon entropy & TXT tunneling detector
│   │   └── arp_spoof.py            # Stateful ARP IP-to-MAC & L2 header mismatch detector
│   └── web/
│       ├── app.py                  # Flask REST API & SOC dashboard server
│       ├── templates/index.html    # Offline-ready 4-tab SOC interface
│       └── static/                 # CSS & JavaScript with inline SVG telemetry charts
├── samples/                        # 6 ready-to-use demonstration .pcap captures
├── docs/                           # Architecture, schema, and operational documentation
└── tests/                          # Comprehensive pytest edge-case & API test suite
```

---

## 2. Permissions for Live Packet Capture & `nftables`

- **Offline `.pcap` / `.pcapng` analysis & Web UI:** Requires **no root privileges**. Run normally as an unprivileged user.
- **Live interface sniffing (`netguard live -i eth0`):** Requires raw socket capture privileges (`CAP_NET_RAW`):
  - Option A (Recommended): run with `sudo .venv/bin/netguard live -i eth0`
  - Option B (Non-root capability on Linux): grant `cap_net_raw` to your Python binary or run inside a network-lab container.
- **Live firewall quarantine (`--live-quarantine`):** Requires `CAP_NET_ADMIN` / `root` and the `nft` userspace utility (`nftables`). By default, NetGuard always uses `--quarantine` (**dry-run**) unless `--live-quarantine` is explicitly passed.

---

## 3. Detection Engine Deep Dive

### 3.1 Port & Stealth Scan Detector (`PortScanDetector`)

Classifies TCP reconnaissance probes by masking the TCP flags byte with `0x3F` to strip ECN bits (`ECE = 0x40`, `CWR = 0x80` per RFC 3168):

| Scan Type | 6-Bit Masked Flags | Hex | Alert Type | Default Threshold | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Half-Open SYN | `SYN` | `0x02` | `TCP_SYN_SCAN` | 15 unique ports / 10s | `HIGH` |
| FIN Stealth | `FIN` | `0x01` | `TCP_FIN_SCAN` | 5 unique ports / 10s | `CRITICAL` |
| NULL Stealth | *(none)* | `0x00` | `TCP_NULL_SCAN` | 5 unique ports / 10s | `CRITICAL` |
| Xmas Tree | `FIN \| PSH \| URG` | `0x29` | `TCP_XMAS_SCAN` | 5 unique ports / 10s | `CRITICAL` |

**False-Positive Protections:**
1. **Completed Handshake Exclusion (`track_half_open_only=True`):** When a client sends an `ACK` without `SYN` (`(flags & 0x10) != 0 and (flags & 0x02) == 0`), the matching 4-tuple `(src_ip, sport, dst_ip, dport)` is evicted from the SYN window. Legitimate browsers/microservices opening many connections do not trigger SYN-scan alerts.
2. **Unique Port Counting:** Repeated `SYN` retransmissions to a single dead port (e.g., 50 retries to `:443`) count as `1` unique port.
3. **Packet-Timestamp Sliding Window:** Every window calculation uses the capture's `pkt.time` high-water mark (`[hw - window, hw]`), never wall-clock `time.time()`. Minor out-of-order packets within the active window are sorted into place; stale packets older than `hw - window` are ignored.

### 3.2 DNS Tunneling Detector (`DnsTunnelDetector`)

Computes base-2 **Shannon entropy** on the subdomain portion of DNS queries (`qr == 0`):

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

- **Worked Example:**
  - Normal subdomain `"www"` (3 chars): below `dns_min_subdomain_len=20` and low entropy (`0.92` bits/char) -> **benign**.
  - Repeated pattern `"a1a1...a1"` (56 chars): `H = 1.00`, exceeds `dns_max_subdomain_len=50` -> **`DNS_LONG_SUBDOMAIN`**.
  - Base64 exfil `"eyJzZWNyZXQiOiJBSXpUOXFCN2s0TDJtOFhwMVFyM1p0NVZ3In0.exfil"` (`TXT`, 57 chars): `H = 4.90 >= 3.8` and length `>= 45` -> **`DNS_TXT_TUNNELING` (`CRITICAL`)**.

**Consolidated Single-Alert Rule:** If a `TXT` query matches multiple heuristics (e.g., high entropy + long subdomain + TXT type), NetGuard emits **one** consolidated `DNS_TXT_TUNNELING` alert listing every matched heuristic in `evidence.triggers`.

### 3.3 ARP Spoofing Detector (`ArpSpoofDetector`)

Tracks IP-to-MAC mappings from ARP requests (`op=1`) and replies (`op=2`):

- **Ground-Truth Preservation:** On an IP-to-MAC conflict, `ArpSpoofDetector` emits `ARP_IP_MAC_CONFLICT` (`CRITICAL`) while preserving the original (or `--arp-static`) MAC in the binding table and recording the attacker's MAC under `conflicting_macs`.
- **RFC 5227 Probe Filtering:** Duplicate Address Detection probes (`psrc == 0.0.0.0`) and zero/broadcast hardware addresses are excluded from table pollution.
- **L2 Header Mismatch:** Flags frames where `Ether.src != ARP.hwsrc` (`ARP_HEADER_MISMATCH`, `HIGH`).

---

## 4. CLI Reference

### Analyze Offline PCAP

```bash
.venv/bin/netguard analyze <pcap_path> [OPTIONS]
```

Key flags:
- `--json <path>` / `--jsonl <path>`: Export structured JSON report or SIEM JSONL alerts.
- `--quarantine`: Enable automated `nftables` evaluation in safe dry-run mode.
- `--live-quarantine`: Execute real `nft` rules (requires root + `nft`).
- `--allowlist <CIDR>`: Repeatable CIDR/IP exempt from quarantine (e.g., `--allowlist 192.168.10.1/32`).
- `--window <sec>`: Sliding time window (default: `10.0`).
- `--syn-threshold <N>` / `--stealth-threshold <N>`: Unique port thresholds (defaults: `15`, `5`).
- `--dns-entropy <float>` / `--dns-max-len <N>` / `--dns-txt-len <N>`: DNS heuristics.
- `--dns-allowlist <domain>`: Repeatable trusted suffix (e.g., `--dns-allowlist cloudfront.net`).
- `--arp-static <IP=MAC>`: Repeatable trusted gateway/server MAC binding (e.g., `--arp-static 192.168.10.1=aa:bb:cc:00:00:01`).
- `--arp-ignore <IP>`: Repeatable failover/VRRP VIP to ignore.

### Live Interface Sniffing

```bash
sudo .venv/bin/netguard live -i eth0 --filter "tcp or udp port 53 or arp" --jsonl /tmp/live.jsonl --quarantine
```

Press `Ctrl+C` (`SIGINT`) to stop capture gracefully and print the session summary.

### Quarantine Administration

```bash
# Print declarative nftables table & chains
.venv/bin/netguard quarantine --print-ruleset

# Inspect active kernel drops (add --live for kernel state)
sudo .venv/bin/netguard quarantine --list --live

# Unblock a single IP or flush the entire NetGuard table
sudo .venv/bin/netguard quarantine --unblock 203.0.113.45 --live
sudo .venv/bin/netguard quarantine --flush --live
```

### Web Dashboard & Sample Generator

```bash
.venv/bin/netguard web --host 127.0.0.1 --port 8080
.venv/bin/netguard generate-samples --output-dir samples
```

---

## 5. SOC Web Dashboard Walkthrough

1. **Threat Analyzer:**
   - Click **Analyze** on any of the 6 built-in `.pcap` cards or drop your own `.pcap` file into the upload box.
   - Click **Detector & Quarantine Tuning** to experiment with parameters (for example, load `06_edge_cases_stress.pcap`, change **Scan Window** from `10` to `60`, and click **Re-run Analysis**).
   - Filter alerts by severity or keyword, inspect MITRE ATT&CK evidence on the right pane, and download **JSON** or **JSONL** exports.
2. **Forensic Telemetry:**
   - Inspect inline SVG charts for **Protocol Distribution**, **Packet & Alert Timeline**, **DNS Shannon Entropy vs Subdomain Length Scatter Plot** (with live threshold crosshairs), **Top Probed TCP Ports**, and the **ARP Binding Table**.
3. **nftables Quarantine:**
   - Review which alert IPs triggered `dry_run` drops vs. `skipped_allowlisted` safety protections, and test custom CIDRs in the interactive simulator.
4. **System Architecture:**
   - Review the end-to-end architecture SVG diagram and MITRE ATT&CK coverage matrix.

---

## 6. Automated `nftables` Quarantine & Rollback

NetGuard isolates all rules inside a dedicated `inet` table (default `table inet netguard`) so it never interferes with existing `iptables` or distribution firewall rules:

```nft
table inet netguard {
    set blocked_ipv4 {
        type ipv4_addr
        flags timeout
    }

    set blocked_ipv6 {
        type ipv6_addr
        flags timeout
    }

    chain quarantine_input {
        type filter hook input priority filter; policy accept;
        ip saddr @blocked_ipv4 counter drop
        ip6 saddr @blocked_ipv6 counter drop
    }
}
```

**Built-in Non-Blockable Safety Ranges:**
- IPv4: `127.0.0.0/8` (loopback), `0.0.0.0/32`, `169.254.0.0/16` (link-local), `224.0.0.0/4` (multicast), `255.255.255.255/32`
- IPv6: `::1/128`, `::/128`, `fe80::/10`, `ff00::/8`
- Plus every CIDR supplied via `--allowlist` / `allowlist_cidrs`.

**Web Safety Guard:** The Flask Web UI enforces `dry_run=True` on all API requests unless the operator explicitly exports `NETGUARD_WEB_ALLOW_LIVE_NFT=1`.

---

## 7. False-Positive Tuning Playbook

| Symptom | Root Cause | Remediation |
| :--- | :--- | :--- |
| CDN / SaaS domains triggering `DNS_HIGH_ENTROPY` | Content delivery hashes in subdomains (`d1a2b3...cloudfront.net`) | Add trusted domain via `--dns-allowlist cloudfront.net` or raise `--dns-entropy 4.1` |
| VRRP / HSRP failover triggering `ARP_IP_MAC_CONFLICT` | Intentional virtual router MAC failover | Add VIP to `--arp-ignore 192.168.10.254` and pin real hosts with `--arp-static` |
| Gateway spoofing in an attacker-first capture | Attacker sends spoofed ARP before real gateway speaks | Pin known infrastructure with `--arp-static 192.168.10.1=aa:bb:cc:00:00:01` |
| Slow port scans evading default 10s window | Scanner pauses 3–5 seconds between probes | Increase `--window 60` (and raise `--cooldown 60` if needed) |

---

## 8. Edge-Case Testing Matrix

All edge cases below are automatically covered in `tests/`:

- **Port Scan:** Exact threshold boundary (`N-1` vs `N`), completed 3-way handshake exclusion, single-port SYN retransmissions, sliding window expiration, out-of-order & stale timestamps, ECN-flagged `SYN|ECE|CWR`, `SYN+ACK` / `FIN+ACK` non-alerts, `FIN` / `NULL` / `Xmas`, IPv6 scans, cooldown suppression & post-cooldown re-alert.
- **DNS Tunneling:** Empty/single-char Shannon entropy, short random subdomains (`< 20` chars), consolidated `TXT` tunneling, low-entropy long subdomains, `in-addr.arpa`/`ip6.arpa`/`.local`/`_dmarc.`/custom allowlists, 2-part TLDs (`co.uk`), DNS responses (`qr=1`), TCP DNS, IPv6 DNS, malformed non-UTF8 / truncated / missing-`DNSQR` packets.
- **ARP Spoofing:** Baseline learning, IP-to-MAC flip preserving ground truth, static binding conflict on first packet, RFC 5227 `0.0.0.0` probes, zero/broadcast MACs, `Ether.src != ARP.hwsrc` mismatch, case-insensitive MAC normalization, ignored failover IPs.
- **Quarantine & Security:** Injection-character IP rejection, loopback/link-local/multicast/custom CIDR allowlist blocks, dry-run IPv4/IPv6 command checks, mocked live `nft` execution, graceful non-root/missing-`nft` error handling, Flask upload path-traversal & empty/corrupt PCAP rejection.

---

## 9. Troubleshooting FAQ

- **`PermissionError` during `netguard live`:** Live sniffing requires `sudo` or `CAP_NET_RAW`. Use offline PCAP analysis or run with `sudo`.
- **"`nft` binary not found" or "requires root privileges":** Dry-run mode (`--quarantine`) works without `nft` or root. Only `--live-quarantine` invokes `/usr/bin/nft` as root.
- **Port 8080 already in use:** Run `.venv/bin/netguard web --port 8090`.
