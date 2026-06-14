<div align="center">

<img src="resources/logos/raw/icon.png" alt="Arwah Logo" width="120"/>

# Arwah

**Next-generation network security sniffer and traffic analyzer**

[![CI](https://github.com/Alinthropisc/Arwah/actions/workflows/ci.yml/badge.svg)](https://github.com/Alinthropisc/Arwah/actions/workflows/ci.yml)
[![Tests](https://github.com/Alinthropisc/Arwah/actions/workflows/tests.yml/badge.svg)](https://github.com/Alinthropisc/Arwah/actions/workflows/tests.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org)

*High-performance packet capture · Deep packet inspection · Real-time alerting · Suricata EVE output*

</div>

---

## What is Arwah?

Arwah is a modern, zero-copy network sniffer and IDS sensor written in Rust with C23 BPF/protocol dissectors. It combines ideas from Wireshark, tcpdump, NetSniff-NG, and Suricata into a single fast CLI tool with an optional TUI dashboard.

```
arwah -i eth0                          # live capture with TUI
arwah -i eth0 --eve /tmp/eve.json      # Suricata-compatible EVE JSON output
arwah -r capture.pcap --filter "tcp"  # replay PCAP with BPF filter
arwah -i eth0 -C 100 -G 3600          # rotating PCAP: 100 MB / 1 hour
arwah -i eth0 --blacklist /etc/arwah/blocklist.txt
```

---

## Features

| Category | Feature | Inspired by |
|----------|---------|-------------|
| **Capture** | Live capture via libpcap | tcpdump |
| **Capture** | AF_PACKET TPACKET_V3 zero-copy (Linux) | NetSniff-NG |
| **Capture** | PCAP file replay | Wireshark |
| **Capture** | Rotating PCAP `-C` (size) / `-G` (time) | tcpdump |
| **Dissection** | Ethernet, VLAN, IPv4/v6, TCP, UDP, ICMP | Wireshark |
| **Dissection** | DNS compressed labels, TLS SNI extraction | Wireshark |
| **DPI** | HTTP, TLS, DNS, SSH, QUIC, WireGuard detection | Suricata |
| **Analysis** | Lock-free flow tracking (DashMap) | Suricata |
| **Analysis** | Per-protocol flow timeouts (TCP/UDP/ICMP) | Suricata |
| **Analysis** | TCP stream reassembly | tcpdump follow-stream |
| **Detection** | SYN flood, ICMP flood detection | Suricata |
| **Detection** | Vertical + horizontal port scan detection | Suricata |
| **Detection** | IP / domain blacklist | Suricata |
| **Detection** | Suspicious ports, bad TTL | Suricata |
| **Output** | Suricata-compatible EVE JSON | Suricata |
| **Output** | Real-time TUI dashboard | NetSniff-NG |
| **Geo** | MaxMind GeoLite2 country + ASN lookup | — |
| **Filter** | BPF filter compilation (C23 interpreter) | tcpdump |
| **Filter** | Wireshark-style display filters | Wireshark |

---

## Architecture

```
arwah (CLI + TUI)
│
├── arwah-engine/          Async capture & analysis engine
│   ├── capture/
│   │   ├── live.rs        libpcap live capture
│   │   ├── afpacket.rs    AF_PACKET zero-copy (Linux)
│   │   └── pcap_file.rs   PCAP file replay
│   ├── analysis/
│   │   ├── dissector.rs   etherparse packet decoder
│   │   └── flow_tracker.rs  DashMap lock-free flow table (per-protocol timeouts)
│   ├── dpi/               Chain-of-Responsibility DPI detectors
│   ├── alert/             Observer alert rules (SYN/ICMP flood, port scan, blacklist)
│   ├── output/
│   │   ├── eve.rs         Suricata EVE JSON writer
│   │   └── rotating_pcap.rs  -C/-G rotating capture
│   ├── blacklist/         IP + domain blocklist (HashSet)
│   ├── stream/            TCP stream reassembly
│   ├── geo/               MaxMind mmdb lookup
│   └── stats/             Rolling traffic statistics
│
├── b579-core/             Shared contracts (traits + types)
│
├── bpf/                   C23 BPF interpreter
│   ├── bpf.h
│   └── bpf_exec.c
│
└── proto/                 C23 protocol dissectors
    ├── proto.h
    ├── eth.c  ip4.c  ip6.c  tcp.c  udp.c  icmp.c  dns.c  tls.c
    └── checksum.c
```

**Design patterns:** Chain of Responsibility (DPI) · Observer (AlertEngine) · Strategy (PacketFilter) · Repository (FlowTracker)

---

## Quick Start

### Requirements

- Rust 1.85+ (2024 edition)
- Clang 18+ (for C23 BPF/proto compilation)
- libpcap dev headers

```bash
# Ubuntu / Debian
sudo apt install libpcap-dev clang-18

# macOS
brew install libpcap llvm
```

### Build

```bash
git clone https://github.com/Alinthropisc/Arwah.git
cd Arwah
cargo build --release
sudo ./target/release/arwah -i eth0
```

### Usage

```bash
# Live capture — TUI dashboard
arwah -i eth0

# Live capture with EVE JSON output
arwah -i eth0 --eve /var/log/arwah/eve.json

# Replay PCAP file
arwah -r /path/to/capture.pcap

# BPF filter
arwah -i eth0 -f "tcp port 443"

# Rotating PCAP: rotate every 100 MB or every hour
arwah -i eth0 -w /captures/traffic -C 100 -G 3600

# IP/domain blacklist
arwah -i eth0 --blacklist /etc/arwah/blocklist.txt

# Geo lookup with MaxMind DB
arwah -i eth0 --geo resources/DB/GeoLite2-Country.mmdb
```

---

## EVE JSON Output

Arwah emits [Suricata-compatible EVE JSON](https://suricata.readthedocs.io/en/latest/output/eve/eve-json-output.html) for alerts and flows:

```json
{"timestamp":"2026-06-14T19:00:00.000Z","event_type":"alert","src_ip":"10.0.0.1","src_port":54321,"dest_ip":"192.168.1.1","dest_port":22,"proto":"TCP","alert":{"action":"allowed","signature":"SYN flood from 10.0.0.1","category":"SynFlood","severity":2}}
{"timestamp":"2026-06-14T19:00:01.000Z","event_type":"flow","src_ip":"10.0.0.1","src_port":54321,"dest_ip":"192.168.1.1","dest_port":22,"proto":"TCP","flow":{"pkts_toserver":100,"pkts_toclient":80,"bytes_toserver":6400,"bytes_toclient":5120,"start":"2026-06-14T18:59:00.000Z","end":"2026-06-14T19:00:01.000Z","state":"established"}}
```

Compatible with Elastic SIEM, Kibana, Grafana, Logstash.

---

## Alert Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| SYN Flood | > 200 SYNs from same source | High |
| ICMP Flood | > 500 ICMPs from same source | Medium |
| Vertical Port Scan | 1 src → 1 dst, > 20 unique ports | High |
| Horizontal Port Scan | 1 src, same port → > 15 hosts | High |
| IP Blacklist hit | packet src/dst matches blocklist | Critical |
| Domain Blacklist hit | DNS query matches blocklist | Critical |
| Bad TTL | TTL ≤ 1 on non-ICMP packet | Low |
| Suspicious Port | dst port in known C2 list | Medium |

---

## Flow Timeouts

| Protocol | State | Timeout |
|----------|-------|---------|
| TCP | SYN only | 60s |
| TCP | Established | 300s |
| TCP | Closing (FIN/RST) | 15s |
| UDP | — | 30s |
| ICMP | — | 10s |
| Other | — | 120s |

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
