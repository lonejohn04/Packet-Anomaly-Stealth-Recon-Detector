# NetGuard Sample PCAP Catalog & Demo Walkthrough

All six `.pcap` files in this directory are deterministically generated via `netguard generate-samples` with realistic Ethernet/IP/TCP/UDP/DNS/ARP headers and exact capture timestamps starting at `1700000000.0` (`2023-11-14T22:13:20Z`).

You can analyze any file directly in the **NetGuard Web Dashboard** (`Threat Analyzer` tab -> **Demonstration Sample Captures**) or from the CLI.

---

## Sample Inventory

### 1. `01_stealth_port_scans.pcap` (137 packets)
- **Benign Traffic Included:**
  - `192.168.10.25 -> 192.168.10.10`: 16 completed TCP 3-way handshakes (`SYN` -> `SYN+ACK` -> `ACK` -> `PSH+ACK`) across 16 distinct ports. Excluded by `track_half_open_only=True`.
  - `192.168.10.30 -> 192.168.10.10:443`: 18 `SYN` retransmissions to a single destination port (unique ports = 1 < 15).
- **Attack Traffic:**
  - `203.0.113.45`: Half-open `SYN` scan across 25 ports (`TCP_SYN_SCAN`, `HIGH`).
  - `198.51.100.77`: Stealth `FIN` scan across 10 ports (`TCP_FIN_SCAN`, `CRITICAL`).
  - `198.51.100.88`: Stealth `NULL` scan across 10 ports (`TCP_NULL_SCAN`, `CRITICAL`).
  - `198.51.100.99`: Stealth `Xmas` (`FIN|PSH|URG`) scan across 10 ports (`TCP_XMAS_SCAN`, `CRITICAL`).

### 2. `02_dns_tunneling.pcap` (12 packets)
- **Benign Traffic Included:** Standard `A`/`AAAA`/`MX` lookups plus `in-addr.arpa` PTR, `_dmarc.`, and `_acme-challenge.` TXT queries (skipped by allowlists).
- **Attack Traffic:**
  - `192.168.10.66`: Two high-entropy Base64-like `A` queries (`DNS_HIGH_ENTROPY`, `HIGH`, entropy ~4.88 and ~5.27).
  - `192.168.10.66`: Two oversized high-entropy `TXT` exfiltration queries (`DNS_TXT_TUNNELING`, `CRITICAL`).
  - `192.168.10.67`: Low-entropy (`1.0` bits/char) 56-char subdomain (`DNS_LONG_SUBDOMAIN`, `MEDIUM`).

### 3. `03_arp_spoofing.pcap` (10 packets)
- **Benign Traffic Included:** RFC 5227 Duplicate Address Detection probe (`psrc=0.0.0.0`) and normal ARP bindings for `192.168.10.1`, `.2`, and `.25`.
- **Attack Traffic:**
  - Spoofed gratuitous ARP replies claiming gateway `192.168.10.1` belongs to `de:ad:be:ef:13:37` (`ARP_IP_MAC_CONFLICT`, `CRITICAL`).
  - Forged ARP reply with `Ether.src=de:ad:be:ef:13:37` != `ARP.hwsrc=aa:bb:cc:00:00:02` (`ARP_HEADER_MISMATCH`, `HIGH`).

### 4. `04_full_killchain_demo.pcap` (37 packets)
- **Multi-Stage SOC Scenario:** Combines normal baseline traffic with external `SYN` + `Xmas` scans, internal gateway ARP poisoning, and DNS `A` + `TXT` data exfiltration (**5 alerts** across all 3 detectors).

### 5. `05_benign_baseline.pcap` (126 packets)
- **False-Positive Resistance Benchmark:** 20 completed TCP handshakes + `FIN+ACK` teardowns, 12 single-port retries, normal/allowlisted DNS queries + `qr=1` DNS responses, RFC 5227 probes, ICMP, and IPv6 traffic.
- **Expected Alerts:** **0**.

### 6. `06_edge_cases_stress.pcap` (43 packets)
- **Interactive Threshold Tuning & Resilience Lab:**
  - **Slow scan** (`192.0.2.77`, 16 ports spaced 3.0s apart = 45s): silent under default `--window 10`, detected immediately when raised to `--window 60`.
  - **ECN-capable handshake** (`SYN|ECE|CWR` -> `SYN+ACK` -> `ACK`): masked cleanly, 0 alerts.
  - **IPv6 SYN scan** (`2001:db8:dead::42`): triggers `TCP_SYN_SCAN` (`HIGH`) with IPv6 `nftables` drop preview.
  - **Loopback FIN scan** (`127.0.0.1`): triggers `TCP_FIN_SCAN` (`CRITICAL`) and tests built-in `skipped_allowlisted` safety guard.
  - **Malformed non-UTF8 DNS bytes**: dissected safely without exceptions.

---

## 30-Second Live Interview Demo Script

```bash
# 1. Show clean baseline produces 0 false positives
.venv/bin/netguard analyze samples/05_benign_baseline.pcap

# 2. Replay full kill chain with automated nftables quarantine preview
.venv/bin/netguard analyze samples/04_full_killchain_demo.pcap --quarantine

# 3. Demonstrate sliding-window evasion vs detection on slow scans
.venv/bin/netguard analyze samples/06_edge_cases_stress.pcap --quarantine
.venv/bin/netguard analyze samples/06_edge_cases_stress.pcap --window 60 --quarantine
```
