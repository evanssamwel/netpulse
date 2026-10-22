# Network Scanner Suite

A high-performance Python network discovery, security auditing, and inventory tracking tool built on Scapy and standard socket libraries.

---

## Key Features

- 🔍 **ARP Discovery**: Rapid host discovery on local subnets with OUI vendor identification and reverse DNS hostname resolution.
- 🎯 **Subnet Auto-Detection (`--local`)**: Zero-configuration scanning. Automatically identifies your active network interface, local IP, gateway, and CIDR block.
- 📡 **Ping & Latency Sweep (`PING`)**: Multi-threaded ICMP sweep over CIDR subnets or single targets. Measures min/avg/max latency, jitter, packet loss, and round-trip time without requiring root privileges.
- 💻 **OS Fingerprinting via TTL**: Estimates target operating systems (Linux/Android/macOS, Windows, or Cisco/Network devices) and network hop counts from packet Time-To-Live (TTL).
- 🛡 **Multi-Threaded TCP Port Scanner (`TCP`)**: High-speed port scanner supporting safe TCP Connect scans (no root needed) and raw SYN half-open scans (`--syn`), complete with service detection and banner grabbing.
- ⚠ **Security Risk Auditing**: Highlights unencrypted or dangerous exposed services (e.g., Telnet 23, FTP 21, HTTP 80, SMB 445, MySQL 3306, RDP 3389).
- 👁 **Live Watch Mode (`--watch`)**: Continuous background network monitor that alerts with terminal bells and timestamps whenever a new or rogue device joins or leaves the network.
- 🏷 **Device Inventory & Tagging (`TAG`)**: Label and annotate network assets (e.g., "Main Router", "Backup NAS", "Security Cam"). Tags persist across all scans.
- 📊 **Executive HTML, CSV, & JSON Reports**: Generates standalone, dark-themed HTML executive audit reports (100% offline-ready, no CDN needed), CSV tables, and structured JSON.

---

## Installation

### Prerequisites
- Python 3.8+
- Linux / macOS / Unix

```bash
# Clone the repository
git clone https://github.com/evanssamwel/network-scanner.git
cd network-scanner

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Command-Line Usage

```bash
usage: scanner.py [-h] {ARP,TCP,PING,TAG} ...
```

### 1. ARP Discovery (`ARP`)

> [!NOTE]
> ARP packet transmission operates at Layer 2 and requires raw socket privileges. Run with `sudo`.

```bash
# Scan a specific subnet
sudo .venv/bin/python scanner.py ARP 192.168.1.0/24

# Auto-detect your local subnet automatically (zero configuration)
sudo .venv/bin/python scanner.py ARP --local

# Live Watch Mode: monitor network continuously every 15 seconds
sudo .venv/bin/python scanner.py ARP --local --watch 15

# Export discovery results to HTML, CSV, or JSON
sudo .venv/bin/python scanner.py ARP --local --html network_report.html --csv network.csv
```

---

### 2. Ping & Latency Sweep (`PING`)

*No root privileges required.*

```bash
# Ping a single host and check round-trip stats & OS fingerprint
python scanner.py PING 192.168.1.1 -c 4

# Multi-threaded Ping sweep across an entire subnet
python scanner.py PING 192.168.1.0/24 --threads 50

# Auto-detect local network and run a fast ping sweep
python scanner.py PING --local

# Export sweep results to a styled HTML report
python scanner.py PING --local --html ping_audit.html
```

---

### 3. TCP Port Scanner (`TCP`)

```bash
# Scan default top 20 ports (non-root connect scan)
python scanner.py TCP 192.168.1.1

# Scan specific ports with service banner grabbing
python scanner.py TCP 192.168.1.1 21 22 80 443 3306

# Scan a range of ports (e.g. 1 to 1024)
python scanner.py TCP 192.168.1.1 --range 1 1024 --threads 100

# High-speed raw SYN half-open scan (requires root)
sudo .venv/bin/python scanner.py TCP 192.168.1.1 --top-ports 20 --syn

# Export scan with security warnings to HTML
python scanner.py TCP 192.168.1.1 --top-ports 20 --html port_scan.html
```

---

### 4. Device Inventory & Tagging (`TAG`)

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

## Git Fork & Branch Workflow

This repository is configured with a two-branch workflow to easily sync with the original upstream project:

- **`upstream-clean`**: Tracks the original creator's repository (`zeyu2001/network-scanner`). Keep this branch untouched.
- **`master`**: Contains all enhanced features, security auditing, and custom tooling.

### Pulling updates from upstream:
```bash
# Fetch latest upstream changes
git checkout upstream-clean
git pull upstream master

# Merge upstream updates into your enhanced master branch
git checkout master
git merge upstream-clean
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
