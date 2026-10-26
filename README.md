# NetPulse (v2.4.0)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg?logo=linux&logoColor=white)](https://www.linux.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.8.0-red.svg)](https://scapy.net/)
[![Code Style](https://img.shields.io/badge/Architecture-Modular%20v2.0-green.svg)](#architecture)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](#docker-deployment)
[![Tests](https://img.shields.io/badge/Tests-34%20Passing-brightgreen.svg)](#automated-testing)
[![Web App](https://img.shields.io/badge/GUI-NetPulse%20Studio-0ea5e9.svg)](#10-netpulse-studio-web-app-gui--rest-api-serve)

> 📖 **Need a quick cheat sheet for running commands?** See the [QUICKSTART.md](QUICKSTART.md) guide.

A high-performance Python network discovery, security auditing, and asset intelligence suite with an embedded graphical Web Studio designed for system administrators, penetration testers, and home lab enthusiasts.

The project combines Layer 2/3/4 discovery, service and version enumeration, smart device classification, security posture risk scoring (0–100), offline CVE vulnerability auditing, SNMP/SMB reconnaissance, network diff change detection, standalone interactive executive reporting, and an interactive point-and-click Web GUI into a single modular toolkit.

---

## Why NetPulse?

Most command-line scanners either produce raw terminal text that is difficult to parse or require complex external scanning engines and database servers. **NetPulse** fills the gap:

1. **Zero Configuration (`--local`)**: Automatically detects default interface, gateway, and CIDR subnet.
2. **Actionable Risk Scoring (0–100)**: Translates exposed ports into a quantifiable security score with prioritized remediation advice.
3. **Smart Hardware Profiling**: Classifies hosts (e.g. *Router/Gateway*, *Storage NAS*, *Printer*, *Smart IoT*, *Workstation*, *Server*) using combined MAC vendor, hostname, open ports, and TTL signals.
4. **Offline CVE Vulnerability Detection**: Audits software banners against high-impact CVEs (e.g., Apache path traversal, OpenSSH regreSSHion, vsftpd backdoor, EternalBlue) with zero internet dependency.
5. **SNMP & SMB Deep Enumeration**: Extracts MIB-II system metrics (uptime, description, model) and audits SMB dialects and message signing enforcement without brute force.
6. **Historical Change Detection**: Alerts when devices appear, disappear, change hostnames, or switch MAC addresses (potential rogue device / ARP spoof warning).
7. **Visual Network Topology & Interactive Dashboards**: Exports dark-mode HTML reports with live search, filtering, and standalone SVG topology diagrams.

---

## Feature Comparison: NetPulse vs Nmap

| Capability | NetPulse | Nmap (Default CLI) |
| :--- | :---: | :---: |
| **Subnet Auto-Detection (`--local`)** | ✅ Built-in Zero-Config | ❌ Requires manual CIDR |
| **Layer 2 ARP Discovery** | ✅ Rapid with OUI Lookup | ⚠️ Requires `-PR` flag |
| **UDP Service Probing** | ✅ Protocol Payloads (DNS, NTP, SNMP, SSDP) | ⚠️ Slow without NSE tuning |
| **Smart Device Classification** | ✅ Automatic (Router, NAS, IoT, Printer, PC) | ⚠️ Partial OS guess |
| **SNMP System Enumeration** | ✅ Pure Python MIB-II (Uptime, Model) | ⚠️ Requires NSE scripts |
| **SMB Signing & Protocol Audit** | ✅ Built-in Dialect & Signing Check | ⚠️ Requires NSE scripts |
| **Offline CVE Auditing** | ✅ Built-in high-impact CVE engine | ⚠️ Vulners requires internet/API |
| **Live Network Watch Mode** | ✅ Continuous alerts & audible bells | ❌ Not available natively |
| **Persistent Asset Tagging (`TAG`)** | ✅ Built-in friendly labels & notes | ❌ External tool needed |
| **Security Risk Scoring (0–100)** | ✅ Calculated score & remediation | ⚠️ Raw NSE findings only |
| **Historical Diffs & Tracking** | ✅ FirstSeen, TimesSeen, change alerts | ❌ Third-party required (e.g. ndiff) |
| **Interactive Standalone HTML Report** | ✅ Offline Glassmorphic Dashboard | ⚠️ Basic static XML/XSLT |
| **SVG Network Topology Map** | ✅ Standalone & Embedded SVG | ❌ External GUI needed (Zenmap) |

---

## Architecture

The project is structured into a clean, decoupled modular engine:

```text
scanner.py (CLI Entrypoint)
  ├── network_scanner/
  │    ├── discovery/   --> Layer 2 ARP Discovery & Live Watch Loop
  │    ├── scanners/    --> Multi-threaded TCP, UDP, SNMP, SMB & ICMP Sweeps
  │    ├── fingerprint/ --> TTL OS Estimation, Version Detection & Device Profiling
  │    ├── security/    --> Risk Scoring Engine (0-100) & Offline CVE Engine
  │    ├── inventory/   --> Persistent Asset Tagging & Historical Change Tracking
  │    ├── reports/     --> Interactive HTML, SVG Topology, CSV & JSON Exporters
  │    └── utils/       --> Subnet Auto-detection & OUI Vendor Resolvers
```

---

## Key Features

- 🔍 **ARP Discovery (`ARP`)**: High-speed Layer 2 discovery with IEEE OUI vendor resolution, private/randomized MAC detection, and reverse DNS.
- 🎯 **Subnet Auto-Detection (`--local`)**: Zero-config scanning. Automatically binds to the active network interface and gateway.
- 🛡 **Multi-Threaded TCP Scanner (`TCP`)**: High-concurrency socket connect scan (unprivileged) and raw SYN half-open scan (`--syn`, root required).
- 📡 **UDP Service Scanner (`UDP`)**: Probes common UDP infrastructure services (DNS 53, DHCP 67, TFTP 69, NTP 123, SNMP 161, Syslog 514, SSDP 1900, mDNS 5353) with protocol-tailored payloads.
- 🔬 **Service & Version Detection**: Extracts software versions from service banners (e.g., `OpenSSH 8.9p1`, `Apache/2.4.52`, `nginx/1.24`, `MySQL/MariaDB 13.0.2`, `Redis 7.2`).
- 🛡 **Offline CVE Vulnerability Engine**: Matches detected banners against known CVEs with CVSS scores and remediations.
- 🖥 **SNMP MIB-II Enumeration (`SNMP`)**: Extracts device descriptions, hostnames, and uptime without third-party dependencies.
- 🗄 **SMB Protocol & Signing Audit (`SMB`)**: Audits SMBv1 risk, dialect negotiation, and SMB signing enforcement (relaying defense).
- 🏷 **Smart Device Classification**: Categorizes discovered devices (*Router / Gateway*, *NAS / Storage*, *Printer / Scanner*, *Mobile*, *IoT*, *Workstation*, *Server*).
- ⚠ **Automated Security Risk Scoring (0–100)**: Calculates host and network security scores with immediate remediation guidelines.
- 🕒 **Historical Inventory & Diff Tracking**: Tracks `FirstSeen`, `LastSeen`, and `TimesSeen`. Alerts on changed hostnames or MAC addresses.
- 🌐 **SVG Topology Visualizer**: Exports clean SVG network hierarchy diagrams representing routers, gateways, and grouped endpoints.
- 👁 **Live Watch Mode (`--watch`)**: Continuous background monitor alerting on new devices connecting or hosts dropping offline.
- 📊 **Executive Interactive HTML Reports**: Modern dark-themed dashboard with live client-side search, status filters, sorting, and collapsible drawers. 100% offline-ready.

---

## Installation

### Prerequisites
- Python 3.8+
- Linux (Ubuntu, Kali, Parrot OS, Debian, Fedora) or macOS

```bash
# Clone the repository
git clone https://github.com/evanssamwel/netpulse.git
cd netpulse

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## ⚡ Quick Start

### Option A: Launch the Graphical Web App (No CLI typing!)
```bash
# Start NetPulse Studio on port 8080
python scanner.py SERVE --port 8080
```
Open **[http://127.0.0.1:8080/](http://127.0.0.1:8080/)** in your browser to run ping sweeps, port audits, Wi-Fi discovery, GeoIP intel, DNS enumeration, and device tagging with 1-click graphical controls.

### Option B: Run via Command-Line
```bash
# Fast unprivileged local host ping sweep
python scanner.py PING --local

# Fast Layer 2 ARP discovery with OUI hardware classification (requires root)
sudo .venv/bin/python scanner.py ARP --local --html network_audit.html

# Comprehensive TCP port & offline CVE security audit
python scanner.py TCP 192.168.1.1 --top-ports 20
```

---

## Command-Line Reference

```bash
usage: scanner.py [-h] [-v] {ARP,TCP,UDP,SNMP,SMB,DNS,SNIFF,WIFI,GEO,SERVE,CONFIG,PING,TAG} ...
```

### 1. ARP Discovery (`ARP`)

> [!NOTE]
> ARP operates at Layer 2 and requires raw socket privileges. Run with `sudo`.

```bash
# Scan a specific subnet
sudo .venv/bin/python scanner.py ARP 192.168.1.0/24

# Auto-detect your local subnet automatically (zero configuration)
sudo .venv/bin/python scanner.py ARP --local

# Live Watch Mode: monitor network continuously every 15 seconds
sudo .venv/bin/python scanner.py ARP --local --watch 15

# Export discovery results to interactive HTML and visual SVG topology
sudo .venv/bin/python scanner.py ARP --local --html network_report.html --svg topology.svg
```

---

### 2. TCP Port Scanner (`TCP`)

```bash
# Scan default top 20 ports (non-root connect scan)
python scanner.py TCP 192.168.1.1

# Scan specific ports with service version detection and CVE auditing
python scanner.py TCP 192.168.1.1 21 22 80 443 3306

# Scan a range of ports (e.g. 1 to 1024)
python scanner.py TCP 192.168.1.1 --range 1 1024 --threads 100

# High-speed raw SYN half-open scan (requires root)
sudo .venv/bin/python scanner.py TCP 192.168.1.1 --top-ports 20 --syn

# Export scan with security score and remediations to HTML
python scanner.py TCP 192.168.1.1 --top-ports 20 --html port_scan.html
```

---

### 3. UDP Port Scanner (`UDP`)

*No root privileges required for socket probe mode.*

```bash
# Scan common UDP services (DNS, NTP, SNMP, SSDP, mDNS, etc.)
python scanner.py UDP 192.168.1.1

# Scan specific UDP ports
python scanner.py UDP 192.168.1.1 53 123 161 5353

# Scan top N common UDP ports
python scanner.py UDP 192.168.1.1 --top-ports 10

# Export UDP audit to interactive HTML
python scanner.py UDP 192.168.1.1 --html udp_audit.html
```

---

### 4. SNMP MIB-II Enumerator (`SNMP`)

```bash
# Enumerate system metrics (checks public, private, community)
python scanner.py SNMP 192.168.1.1

# Specify a custom community string and export HTML report
python scanner.py SNMP 192.168.1.1 --community corporate_net --html snmp_report.html --theme cyberpunk
```

---

### 5. SMB Protocol & Signing Audit (`SMB`)

```bash
# Audit SMB dialect support, SMBv1 risk, and message signing policy
python scanner.py SMB 192.168.1.1

# Export audit to HTML with Executive Light theme
python scanner.py SMB 192.168.1.1 --html smb_audit.html --theme light
```

---

### 6. DNS Enumeration & AXFR Zone Transfer (`DNS`)

```bash
# Query standard records (A, AAAA, MX, NS, TXT, SOA) and test for AXFR misconfigurations
python scanner.py DNS example.com

# Query using a specific DNS resolver
python scanner.py DNS example.com --server 1.1.1.1 --html dns_audit.html
```

---

### 7. Wireless / Wi-Fi Reconnaissance (`WIFI`)

*Discovers nearby wireless access points, measures signal quality, and audits wireless encryption security (flags open Wi-Fi and WEP).*

```bash
# Scan nearby Wi-Fi networks (uses NetworkManager or iwlist)
python scanner.py WIFI

# Specify wireless interface and export results
python scanner.py WIFI -i wlp2s0 --json wifi_scan.json --csv wifi_scan.csv
```

---

### 8. IP Geolocation & WAN Intelligence (`GEO`)

*Retrieves public IP geolocation, coordinates, ISP, and Autonomous System (ASN) details.*

```bash
# Geolocation lookup for a public host or WAN address
python scanner.py GEO 8.8.8.8

# Export intelligence to JSON
python scanner.py GEO 1.1.1.1 --json geo_intel.json
```

---

### 9. Live Packet Sniffing & PCAP Capture (`SNIFF`)

*Captures and parses live network protocols (ARP, DHCP, DNS, ICMP) with optional Wireshark PCAP output.*

```bash
# Live packet inspection on the default interface
sudo .venv/bin/python scanner.py SNIFF

# Capture 50 packets with a custom BPF filter and save to PCAP
sudo .venv/bin/python scanner.py SNIFF -i eth0 -c 50 -f "port 53 or arp" -w capture.pcap
```

---

### 10. NetPulse Studio Web App GUI & REST API (`SERVE`)

*Instead of typing terminal commands, run scans through a sleek, point-and-click graphical Web App in your browser.*

```bash
# Start the NetPulse Studio Web GUI on port 8080
python scanner.py SERVE --host 127.0.0.1 --port 8080
```

Once running, navigate to **`http://127.0.0.1:8080/`** to access the complete graphical cybersecurity console:

- 📊 **Assets & Inventory**: Live device tracking table, quick search & filtering, CSV/JSON export, and friendly device tagging dialog.
- ⚡ **Subnet Ping Sweep**: One-click host discovery with auto-detected CIDR, concurrency slider, latency metrics, and instant port scan buttons.
- 🔍 **Port & Vulnerability Auditor**: Target IP presets, TCP connect & raw SYN scans, UDP service probes, host risk gauge (0–100), and offline CVE vulnerability lookup.
- 📶 **Wi-Fi Reconnaissance**: Airspace scanner displaying nearby access points, signal strength bars, channels, and insecure open network alerts.
- 🌍 **WAN GeoIP Threat Intel**: External IP lookup showing country, city, ISP, ASN routing, and direct Google Maps coordinate links.
- 🌐 **DNS & AXFR Auditor**: Query A, AAAA, MX, NS, TXT, SOA records and audit authoritative nameservers for dangerous AXFR zone transfer leaks.
- 🛡️ **Automated Remediation**: Generate and copy immediate Linux kernel firewall isolation scripts (`iptables` / `nftables`) for rogue or compromised hosts.
- 🌙 **Multi-Theme Switcher**: Instant switching between **Dark Obsidian**, **Cyberpunk Neon**, and **Executive Light** themes.

Full REST API endpoints:
- `GET /` — NetPulse Studio Interactive Web Application (GUI)
- `GET /api/inventory` — Discovered host assets and lifecycle history
- `GET /api/tags` — Configured device friendly tags and notes
- `GET /api/subnet` — Auto-detected local CIDR subnet and gateway
- `GET /api/wifi/interfaces` — Available wireless network interfaces
- `GET /api/scan/wifi?interface=...` — Scan nearby 802.11 Wi-Fi networks
- `GET /api/scan/geo?ip=...` — Retrieve WAN IP geolocation & ASN intelligence
- `GET /api/scan/dns?target=...` — Query DNS records and test AXFR zone transfer
- `GET /api/export?format=csv|json` — Download inventory data
- `POST /api/scan/ping` — Execute ping sweep or single probe
- `POST /api/scan/tcp` — Audit open TCP ports, banners, and offline CVEs
- `POST /api/scan/udp` — Probe responsive UDP service ports
- `POST /api/tag` — Save friendly device tag and notes
- `POST /api/tag/delete` — Remove friendly tag
- `POST /api/remediation/isolate` — Generate or execute host firewall isolation


---

### 11. Configuration Management (`CONFIG`)

```bash
# View current preferences
python scanner.py CONFIG

# Update default scanning threads or HTML theme
python scanner.py CONFIG --set threads 75
python scanner.py CONFIG --set html_theme light
```

---

### 12. Ping & Latency Sweep (`PING`)

*No root privileges required.*

```bash
# Ping a single host and check round-trip stats, device role & OS fingerprint
python scanner.py PING 192.168.1.1 -c 4

# Multi-threaded Ping sweep across an entire subnet
python scanner.py PING 192.168.1.0/24 --threads 50

# Auto-detect local network and run a fast ping sweep with SVG topology
python scanner.py PING --local --html ping_audit.html --svg ping_topology.svg
```

---

### 13. Device Inventory & Tagging (`TAG`)

Manage friendly aliases and notes for known devices:

```bash
# Add a friendly label and notes to an IP or MAC address
python scanner.py TAG 192.168.1.1 "Main Router" --notes "Fiber gateway in server rack"
python scanner.py TAG 00:11:22:33:44:55 "CEO Laptop" --notes "Authorized executive device"

# List all saved device tags
python scanner.py TAG --list

# Delete a tag
python scanner.py TAG --delete 192.168.1.1
```

---

## Docker Deployment

You can run **NetPulse** without installing local Python dependencies using Docker:

```bash
# Build the Docker image
docker build -t netpulse .

# Run ARP discovery using host networking
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN netpulse ARP --local

# Run a TCP security audit
docker run --rm --net=host netpulse TCP 192.168.1.1 --top-ports 20
```

---

## Automated Testing

The suite includes a comprehensive unit test suite:

```bash
# Run all unit tests
.venv/bin/python -m unittest discover tests
```

---

## Responsible Use

> [!CAUTION]
> This tool is intended solely for authorized network inventory, security auditing, and educational purposes on systems and networks you own or have explicit written permission to test. Unauthorized port scanning or reconnaissance may violate institutional policies or local computer crime laws.

---

## Tested Operating Systems

- **Ubuntu** (20.04, 22.04, 24.04 LTS)
- **Kali Linux** (2023.x / 2024.x)
- **Parrot Security OS**
- **Debian** (11 Bullseye, 12 Bookworm)
- **Fedora** (38, 39, 40)
- **macOS** (Sonoma / Sequoia)

---

## Git Fork & Branch Workflow

This repository is configured with a two-branch workflow:
- **`upstream-clean`**: Tracks the original creator's repository (`zeyu2001/network-scanner`). Keep this branch untouched.
- **`master`**: Contains the enhanced v2.0 suite, modular architecture, and security auditing engines.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
