# 🚀 NetPulse - Quick Execution & Cheat Sheet Guide

> **Quick Reference File**: Keep this handy whenever you return to this project in the future.

---

## ⚡ 1. Starting Up (First Step)

Whenever you open your terminal, navigate to the project directory and activate the virtual environment:

```bash
cd /home/rekcah/Desktop/network-scanner
source .venv/bin/activate
```

Verify everything is working:
```bash
python scanner.py --version
# Expected: scanner.py v2.4.0
```

---

## 🌐 2. Web App GUI Mode (Easiest - Point & Click)

If you don't want to type CLI commands, start the embedded **NetPulse Studio Web GUI**:

```bash
python scanner.py SERVE --port 8080
```

Now open this URL in any browser:
👉 **`http://127.0.0.1:8080/`**

### What you can do from the Web GUI:
- **📊 Assets & Inventory**: View discovered devices, search/filter by vendor or IP, download CSV/JSON, and tag devices with friendly names (e.g., *"Living Room TV"*).
- **⚡ Subnet Discovery**: Click *"Auto-Detect Subnet"* and *"Launch Ping Sweep"* to discover active devices with latency ratings.
- **🔍 Port & CVE Audit**: Audit open ports on any IP, check offline CVE vulnerabilities, and view the **Host Security Risk Meter (0–100)**.
- **📶 Wi-Fi Recon**: Click *"Discover Nearby Wi-Fi"* to view nearby APs, signal strength bars, and insecure open network warnings.
- **🌍 GeoIP Intel**: Enter any public IP or domain to view Country, City, ISP, ASN, and a direct Google Maps button.
- **🌐 DNS & AXFR**: Audit DNS records and test if nameservers have dangerous AXFR zone transfer leaks.
- **🛡️ Remediation**: Click *"Generate Isolation Rules"* to produce instant Linux `iptables` / `nftables` DROP scripts for rogue devices.
- **🌙 Multi-Theme Switcher**: Switch between **Dark Obsidian**, **Cyberpunk Neon**, and **Executive Light** themes.

*(Press `Ctrl+C` in the terminal whenever you want to stop the server).*

---

## 💻 3. Command-Line (CLI) Cheat Sheet

If you prefer using the terminal, here are the most useful commands:

### A. Network Discovery
```bash
# 1. Unprivileged Ping Sweep (auto-detects your local subnet automatically)
python scanner.py PING --local

# 2. Fast Layer 2 ARP scan with hardware vendor lookup & HTML report (requires sudo)
sudo .venv/bin/python scanner.py ARP --local --html reports/network_audit.html --svg reports/topology.svg

# 3. Continuous Watch Mode (alerts every 15s if new devices join or leave)
sudo .venv/bin/python scanner.py ARP --local --watch 15
```

### B. Port & Security Auditing
```bash
# 1. Scan default Top 20 ports on a device (connect scan, no root needed)
python scanner.py TCP 192.168.1.1

# 2. Scan specific ports and check for CVE vulnerabilities
python scanner.py TCP 192.168.1.1 21 22 80 443 3306 8080

# 3. Raw Stealth SYN Scan (high-speed, requires sudo)
sudo .venv/bin/python scanner.py TCP 192.168.1.1 --top-ports 20 --syn

# 4. Probe UDP services (DNS, NTP, SNMP, mDNS)
python scanner.py UDP 192.168.1.1 --top-ports 10
```

### C. Wireless & Threat Intelligence
```bash
# 1. Discover nearby Wi-Fi networks and audit encryption security
python scanner.py WIFI

# 2. Lookup public IP geolocation, ISP, ASN, and coordinates
python scanner.py GEO 8.8.8.8

# 3. Enumerate domain DNS records and test for AXFR zone transfer misconfigurations
python scanner.py DNS google.com
```

### D. Advanced Protocols & Sniffing
```bash
# 1. Query SNMP MIB-II system metrics (uptime, model, hostname)
python scanner.py SNMP 192.168.1.1

# 2. Audit SMB dialects, SMBv1 risk, and message signing enforcement
python scanner.py SMB 192.168.1.1

# 3. Live packet sniffer with Wireshark PCAP export (requires sudo)
sudo .venv/bin/python scanner.py SNIFF -c 50 -w capture.pcap
```

### E. Inventory Tagging & Device Notes
```bash
# 1. Label a device with a friendly alias
python scanner.py TAG 192.168.1.1 "Gateway Router" --notes "Main fiber modem"

# 2. List all saved device tags
python scanner.py TAG --list

# 3. Delete a tag
python scanner.py TAG --delete 192.168.1.1
```

---

## 🧪 4. Running Automated Tests

To verify that the entire codebase is healthy and all modules pass verification:

```bash
.venv/bin/python -m unittest discover tests
# All 34 tests should pass with: OK
```

---

## 🐳 5. Running with Docker

If running on a system without Python installed:

```bash
# Build the Docker container
docker build -t netpulse .

# Run ARP discovery using host networking
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN netpulse ARP --local
```

---

## 🔗 6. Repository & Version Control

- **GitHub Repository**: [https://github.com/evanssamwel/netpulse](https://github.com/evanssamwel/netpulse)
- **Branch**: `master` (Tracked with `origin/master`)
- **Git Push Command**:
  ```bash
  git add .
  git commit -m "your message"
  git push origin master
  ```
