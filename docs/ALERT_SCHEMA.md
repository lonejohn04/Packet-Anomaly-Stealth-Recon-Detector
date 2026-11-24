# NetGuard Alert & Telemetry Schema

NetGuard produces two structured output formats:

1. **Full Analysis Report (`--json`)**: Single JSON object matching `AnalysisResult.to_dict()`.
2. **Streaming Alert Feed (`--jsonl`)**: Newline-delimited JSON (one `Alert` object per line) suitable for **Elastic Filebeat**, **Splunk**, **Wazuh**, or `jq` pipelines.

---

## 1. `Alert` Object Schema

| Field | Type | Description |
| :--- | :--- | :--- |
| `alert_id` | `string` | Sequential detector ID (e.g., `NG-SCAN-0001`, `NG-DNS-0001`, `NG-ARP-0001`) |
| `timestamp` | `string` | ISO-8601 UTC timestamp derived from packet capture time (`YYYY-MM-DDTHH:MM:SS.sssZ`) |
| `packet_timestamp` | `number` | Raw POSIX epoch float of the triggering packet |
| `detector` | `string` | Detector module (`port_scan`, `dns_tunnel`, or `arp_spoof`) |
| `alert_type` | `string` | Machine-readable signature identifier |
| `severity` | `string` | One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `mitre_attack` | `object` | `{ "tactic", "technique_id", "technique_name" }` |
| `src_ip` | `string \| null` | Attacker or claiming IPv4/IPv6 address |
| `dst_ip` | `string \| null` | Target IPv4/IPv6 address (if applicable) |
| `src_mac` | `string \| null` | Lowercase source MAC address |
| `dst_mac` | `string \| null` | Lowercase destination MAC address |
| `summary` | `string` | Human-readable triage summary |
| `evidence` | `object` | Detector-specific forensic telemetry |
| `quarantine_action` | `string` | `none`, `dry_run`, `applied`, `skipped_allowlisted`, `already_quarantined`, `invalid_ip`, or `failed` |
| `quarantine_detail` | `string \| null` | Explanation or exact `nftables` command summary |

---

## 2. Example Alerts by Detector

### Port Scan (`TCP_SYN_SCAN` / `TCP_XMAS_SCAN`)

```json
{
  "alert_id": "NG-SCAN-0001",
  "timestamp": "2023-11-14T22:13:24.400Z",
  "packet_timestamp": 1700000004.4,
  "detector": "port_scan",
  "alert_type": "TCP_SYN_SCAN",
  "severity": "HIGH",
  "mitre_attack": {
    "tactic": "Discovery",
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery"
  },
  "src_ip": "203.0.113.99",
  "dst_ip": "192.168.10.10",
  "src_mac": "aa:00:00:00:05:99",
  "dst_mac": "00:11:22:33:44:10",
  "summary": "SYN port scan detected from 203.0.113.99 against 192.168.10.10: 15 unique ports probed within 10s",
  "evidence": {
    "scan_type": "SYN",
    "unique_port_count": 15,
    "threshold": 15,
    "window_seconds": 10.0,
    "packet_count_in_window": 15,
    "sample_ports": [20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90],
    "tcp_flags_hex": "0x02",
    "raw_tcp_flags_hex": "0x02",
    "half_open_only": true
  },
  "quarantine_action": "dry_run",
  "quarantine_detail": "Dry-run: would drop 203.0.113.99 in inet netguard for 900s"
}
```

### DNS Tunneling (`DNS_TXT_TUNNELING`)

```json
{
  "alert_id": "NG-DNS-0002",
  "timestamp": "2023-11-14T22:13:34.200Z",
  "packet_timestamp": 1700000014.2,
  "detector": "dns_tunnel",
  "alert_type": "DNS_TXT_TUNNELING",
  "severity": "CRITICAL",
  "mitre_attack": {
    "tactic": "Exfiltration",
    "technique_id": "T1048.003",
    "technique_name": "Exfiltration Over Unencrypted Non-C2 Protocol"
  },
  "src_ip": "192.168.10.50",
  "dst_ip": "192.168.10.2",
  "src_mac": "00:11:22:33:44:50",
  "dst_mac": "aa:bb:cc:00:00:02",
  "summary": "Suspected DNS TXT tunneling from 192.168.10.50: eyJzZWNyZXQiOiJBSXpUOXFCN2s0TDJtOFhwMVFyM1p0NVZ3In0.exfil.attacker-c2.ex (entropy=4.90, sub_len=57)",
  "evidence": {
    "qname": "eyJzZWNyZXQiOiJBSXpUOXFCN2s0TDJtOFhwMVFyM1p0NVZ3In0.exfil.attacker-c2.example",
    "base_domain": "attacker-c2.example",
    "subdomain": "eyJzZWNyZXQiOiJBSXpUOXFCN2s0TDJtOFhwMVFyM1p0NVZ3In0.exfil",
    "qtype": 16,
    "qtype_name": "TXT",
    "subdomain_length": 57,
    "fqdn_length": 77,
    "shannon_entropy": 4.9001,
    "entropy_threshold": 3.8,
    "triggers": ["high_entropy", "long_subdomain", "long_txt_query", "txt_record"]
  },
  "quarantine_action": "dry_run",
  "quarantine_detail": "Dry-run: would drop 192.168.10.50 in inet netguard for 900s"
}
```

### ARP Spoofing (`ARP_IP_MAC_CONFLICT`)

```json
{
  "alert_id": "NG-ARP-0001",
  "timestamp": "2023-11-14T22:13:30.000Z",
  "packet_timestamp": 1700000010.0,
  "detector": "arp_spoof",
  "alert_type": "ARP_IP_MAC_CONFLICT",
  "severity": "CRITICAL",
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1557.002",
    "technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning"
  },
  "src_ip": "192.168.10.1",
  "dst_ip": "192.168.10.1",
  "src_mac": "de:ad:be:ef:ca:fe",
  "dst_mac": "ff:ff:ff:ff:ff:ff",
  "summary": "ARP spoofing detected for 192.168.10.1: MAC changed from aa:bb:cc:00:00:01 to de:ad:be:ef:ca:fe (gratuitous ARP)",
  "evidence": {
    "ip": "192.168.10.1",
    "original_mac": "aa:bb:cc:00:00:01",
    "spoofed_mac": "de:ad:be:ef:ca:fe",
    "arp_op": 2,
    "arp_op_name": "is-at (reply)",
    "is_gratuitous": true,
    "is_static_binding": false,
    "conflict_count": 1
  },
  "quarantine_action": "dry_run",
  "quarantine_detail": "Dry-run: would drop 192.168.10.1 in inet netguard for 900s"
}
```

---

## 3. Useful `jq` Recipes for SOC Triage

```bash
# List all CRITICAL alerts with source IP and MITRE technique
jq -r 'select(.severity=="CRITICAL") | [.timestamp, .alert_type, .src_ip, .mitre_attack.technique_id] | @tsv' alerts.jsonl

# Summarize alert counts by type from a full JSON report
jq '.alert_type_counts' report.json

# Extract all unique attacker IPs recommended for quarantine
jq -r '.quarantine_records[] | select(.status=="dry_run" or .status=="applied") | .ip' report.json | sort -u
```
