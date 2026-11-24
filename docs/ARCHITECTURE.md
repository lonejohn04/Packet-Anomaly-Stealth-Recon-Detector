# NetGuard System Architecture & Diagrams

This document provides visual architecture, sequence, state-machine, quarantine decision, and deployment topology diagrams for NetGuard.

---

## 1. High-Level Component Architecture

```mermaid
flowchart TB
    subgraph Sources["Traffic Sources"]
        PCAP["Offline .pcap / .pcapng Files"]
        NIC["Live Network Interface (eth0 / lo / wlan0)"]
    end

    subgraph Core["src/netguard/engine.py — PacketAnalyzer"]
        READER["Scapy PcapReader / sniff(store=False)"]
        TS["Safe Timestamp &amp; Protocol Classifier"]
    end

    subgraph Detectors["src/netguard/detectors/"]
        PORT["PortScanDetector<br/>(SYN / FIN / NULL / Xmas)"]
        DNS["DnsTunnelDetector<br/>(Shannon Entropy / TXT Length)"]
        ARP["ArpSpoofDetector<br/>(IP-to-MAC Table / L2 Check)"]
    end

    subgraph Mitigation["src/netguard/quarantine.py"]
        QGATE{"Quarantine Enabled &amp;<br/>Severity >= min_severity?"}
        ALLOW{"Protected Range or<br/>User Allowlist CIDR?"}
        NFT["Linux nftables (table inet netguard)<br/>Dry-Run or Live Drop Element"]
    end

    subgraph Presentation["Outputs &amp; Interfaces"]
        REPORT["alert_io.py<br/>JSON Report &amp; JSONL Feed"]
        CLI["cli.py<br/>Rich Console UI"]
        WEB["web/app.py<br/>Flask SOC Dashboard"]
    end

    PCAP --> READER
    NIC --> READER
    READER --> TS
    TS --> PORT & DNS & ARP
    PORT & DNS & ARP -->|"Alert[]"| QGATE
    QGATE -->|"Yes"| ALLOW
    QGATE -->|"No"| REPORT
    ALLOW -->|"Protected (Skip)"| REPORT
    ALLOW -->|"Blockable IP"| NFT
    NFT --> REPORT
    REPORT --> CLI & WEB
```

### Terminal ASCII Reference Diagram

```text
  [.pcap / .pcapng] ──┐
                      ├──> [PacketAnalyzer] ──┬──> [PortScanDetector]  (SYN/FIN/NULL/Xmas)
  [Live Interface]  ──┘                       ├──> [DnsTunnelDetector] (Entropy / TXT Size)
                                              └──> [ArpSpoofDetector]  (IP<->MAC Conflicts)
                                                           │
                                                           ▼
                                               [MITRE Alert Pipeline]
                                                 ├──> JSON / JSONL Export
                                                 ├──> Rich CLI / Flask SOC UI
                                                 └──> [NftablesQuarantineManager]
                                                        ├── Protected / Allowlist -> Skip
                                                        └── Threat IP -> nft add element (timeout)
```

---

## 2. Packet Processing & Quarantine Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Src as PCAP / Live NIC
    participant Eng as PacketAnalyzer
    participant Det as Detectors (TCP/DNS/ARP)
    participant Q as NftablesQuarantineManager
    participant Out as JSONL / CLI / Web UI

    Src->>Eng: Deliver raw packet + pkt.time
    Eng->>Eng: Classify protocol &amp; update timeline bucket
    Eng->>Det: process_packet(pkt, pkt_ts)
    alt Malformed layer payload
        Det-->>Eng: Safely skip bad layer (no crash)
    else Benign or below threshold
        Det-->>Eng: []
    else Anomaly threshold breached
        Det-->>Eng: Alert (with MITRE ATT&amp;CK &amp; Evidence)
        Eng->>Q: evaluate_alert(alert)
        alt Quarantine disabled or below min_severity
            Q-->>Eng: quarantine_action = "none"
        else Protected loopback/link-local/allowlist IP
            Q-->>Eng: quarantine_action = "skipped_allowlisted"
        else Dry-run mode
            Q-->>Eng: quarantine_action = "dry_run" + nft cmd preview
        else Live root mode with nft binary
            Q->>Q: subprocess.run(["nft", "add", "element", ...])
            Q-->>Eng: quarantine_action = "applied"
        end
        Eng->>Out: Emit enriched Alert &amp; update telemetry
    end
```

---

## 3. PortScanDetector Sliding-Window State Machine

```mermaid
stateDiagram-v2
    [*] --> InspectTCP: Packet has TCP + (IP or IPv6)
    InspectTCP --> CompletedHandshake: "track_half_open_only AND (ACK &amp;&amp; !SYN)"
    CompletedHandshake --> [*]: "Remove (sport, dport) from SYN window"

    InspectTCP --> ClassifyProbe: "Mask flags = raw_flags &amp; 0x3F"
    ClassifyProbe --> [*]: "Flags not SYN(0x02), FIN(0x01), NULL(0x00), XMAS(0x29)"
    ClassifyProbe --> CheckStale: "Matched scan probe type"

    CheckStale --> [*]: "pkt_ts < high_water_ts - window (stale packet)"
    CheckStale --> UpdateWindow: "pkt_ts within active horizon"

    UpdateWindow --> EvictExpired: "Insert sorted (pkt_ts, dport, sport)"
    EvictExpired --> CheckThreshold: "Drop entries < high_water_ts - window"

    CheckThreshold --> [*]: "unique_ports < threshold"
    CheckThreshold --> CheckCooldown: "unique_ports >= threshold"

    CheckCooldown --> [*]: "high_water_ts - last_alert < cooldown"
    CheckCooldown --> EmitAlert: "Cooldown satisfied -> Emit Alert"
    EmitAlert --> [*]
```

---

## 4. `nftables` Quarantine Decision Flow

```mermaid
flowchart TD
    START(["Alert Emitted"]) --> CHECK_EN{"quarantine.enabled == True?"}
    CHECK_EN -- No --> NONE["action = 'none'"]
    CHECK_EN -- Yes --> CHECK_SEV{"severity >= min_severity?"}
    CHECK_SEV -- No --> NONE
    CHECK_SEV -- Yes --> PARSE_IP{"Valid IPv4/IPv6 literal?<br/>(ipaddress.ip_address)"}
    PARSE_IP -- Invalid --> INV["status = 'invalid_ip'"]
    PARSE_IP -- Valid --> PROT{"In built-in protected net<br/>(127/8, 169.254/16, ::1, fe80::/10)<br/>or allowlist_cidrs?"}
    PROT -- Yes --> SKIP["status = 'skipped_allowlisted'"]
    PROT -- No --> DEDUP{"Already in active_blocks?"}
    DEDUP -- Yes --> ALREADY["Reuse active status (no duplicate nft call)"]
    DEDUP -- No --> MODE{"dry_run == True?"}
    MODE -- Yes --> DRY["status = 'dry_run'<br/>Record exact nft argv commands"]
    MODE -- No --> ENV{"nft on PATH &amp;&amp;<br/>geteuid() == 0?"}
    ENV -- No --> FAIL["status = 'failed'<br/>Log actionable remediation"]
    ENV -- Yes --> APPLY["Bootstrap table inet netguard<br/>Run nft add element ... timeout Ns<br/>status = 'applied'"]
```

---

## 5. Recommended Home-Lab Deployment Topology

```mermaid
flowchart LR
    ATK["External Attacker VM<br/>(Kali / Scapy)<br/>203.0.113.0/24"] -->|"SYN / FIN / Xmas Scans"| GW["Linux Gateway / Sensor<br/>Running NetGuard + nftables<br/>192.168.10.1"]
    GW -->|"Filtered LAN Traffic"| SRV["Protected Internal Server<br/>192.168.10.10"]
    ROGUE["Compromised LAN Host<br/>192.168.10.50"] -->|"ARP Poisoning &amp; DNS Tunneling"| GW
    GW -->|"JSONL Stream &amp; SOC UI (:8080)"| SOC["Analyst Workstation"]
```
