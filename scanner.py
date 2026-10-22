import argparse
import csv
import html
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Silence Scapy startup messages and emission noise
os.environ["SCAPY_USE_PCAPDNET"] = "False"
from scapy.all import Ether, ARP, IP, TCP, srp, sr, conf  # noqa: E402

conf.verb = 0

HISTORY_FILE = Path(".scanner_history.json")
TAGS_FILE = Path(".scanner_tags.json")

COMMON_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

SECURITY_WARNINGS = {
    21: "FTP transmits credentials and data in cleartext.",
    23: "Telnet is unencrypted and insecure. Use SSH instead.",
    80: "HTTP transmits data in cleartext. Prefer HTTPS (443).",
    135: "RPC endpoint mapper exposed; common target for reconnaissance.",
    139: "NetBIOS Session Service exposed to network.",
    445: "SMB exposed; ensure SMBv1 is disabled and authentication is strict.",
    3306: "MySQL database port exposed. Avoid exposing database ports directly.",
    3389: "RDP exposed. Ensure NLA is enabled and strong passwords or VPN are used.",
    5432: "PostgreSQL database port exposed. Ensure access is restricted.",
    5900: "VNC exposed. Ensure strong encryption and authentication.",
}


# ==========================================
# Tags & History Management
# ==========================================

class DeviceTagManager:
    """Manages custom user notes and labels for discovered devices."""

    @staticmethod
    def load_tags():
        if TAGS_FILE.exists():
            try:
                with open(TAGS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    @staticmethod
    def save_tags(tags):
        with open(TAGS_FILE, "w", encoding="utf-8") as f:
            json.dump(tags, f, indent=2)

    @classmethod
    def set_tag(cls, identifier, label, notes=""):
        tags = cls.load_tags()
        tags[identifier] = {
            "label": label,
            "notes": notes,
            "updated_at": datetime.now().isoformat()
        }
        cls.save_tags(tags)

    @classmethod
    def get_tag(cls, *identifiers):
        tags = cls.load_tags()
        for ident in identifiers:
            if ident and ident in tags:
                return tags[ident]
        return None

    @classmethod
    def delete_tag(cls, identifier):
        tags = cls.load_tags()
        if identifier in tags:
            del tags[identifier]
            cls.save_tags(tags)
            return True
        return False


class ScanHistoryManager:
    """Tracks scan history to detect NEW, ONLINE, and OFFLINE devices."""

    @staticmethod
    def load_last_scan():
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("devices", {})
            except Exception:
                return {}
        return {}

    @staticmethod
    def save_scan(current_devices):
        data = {
            "timestamp": datetime.now().isoformat(),
            "devices": {
                d["IP"]: {
                    "MAC": d.get("MAC", ""),
                    "Vendor": d.get("Vendor", ""),
                    "Hostname": d.get("Hostname", ""),
                    "LastSeen": datetime.now().isoformat()
                }
                for d in current_devices
                if "IP" in d
            }
        }
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


# ==========================================
# Hardware & Network Resolution
# ==========================================

def int2ip(val):
    """Converts a 32-bit integer into a dotted-quad IPv4 string."""
    return socket.inet_ntoa(struct.pack("!I", val))


def get_local_subnet():
    """
    Auto-detects the active network interface, local IP, gateway, and CIDR subnet.
    Returns:
        dict: {
            "interface": str,
            "ip": str,
            "gateway": str,
            "cidr": str
        }
    """
    try:
        iface, local_ip, gw = conf.route.route("8.8.8.8")
    except Exception:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        return {
            "interface": "default",
            "ip": local_ip,
            "gateway": "unknown",
            "cidr": str(ipaddress.IPv4Interface(f"{local_ip}/24").network)
        }

    detected_cidr = None
    for net, msk, gateway, route_iface, addr, metric in conf.route.routes:
        if route_iface == iface and gateway == "0.0.0.0" and msk != 0:
            try:
                net_str = int2ip(net)
                msk_str = int2ip(msk)
                net_obj = ipaddress.IPv4Network(f"{net_str}/{msk_str}", strict=False)
                if net_obj.num_addresses > 2:
                    detected_cidr = str(net_obj)
                    break
            except Exception:
                continue

    if not detected_cidr:
        detected_cidr = str(ipaddress.IPv4Interface(f"{local_ip}/24").network)

    return {
        "interface": iface,
        "ip": local_ip,
        "gateway": gw,
        "cidr": detected_cidr
    }


def resolve_mac_vendor(mac):
    """
    Resolves the vendor/manufacturer from MAC address prefix.
    Detects locally administered / randomized MAC addresses.
    """
    if not mac or mac == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"

    try:
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 2:
            return "Randomized / Private MAC"
    except Exception:
        pass

    try:
        vendor_resolved = conf.manufdb._resolve_MAC(mac)
        if vendor_resolved and vendor_resolved != mac:
            parts = vendor_resolved.split(":")
            if len(parts) > 1 and parts[0]:
                return parts[0]
            return vendor_resolved
    except Exception:
        pass

    return "Unknown Vendor"


def resolve_hostname(ip):
    """Performs reverse DNS lookup to identify hostname."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""


def get_service_name(port):
    """Retrieves standard service name for a given port."""
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        common = {
            80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            3306: "MYSQL", 5432: "POSTGRESQL", 27017: "MONGODB", 6379: "REDIS",
            3389: "RDP", 22: "SSH", 21: "FTP", 23: "TELNET", 53: "DNS", 445: "SMB"
        }
        return common.get(port, "UNKNOWN")


def grab_banner(ip, port, timeout=1.0):
    """Attempts to grab a service banner for open ports."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (21, 22, 25, 110):
                pass
            else:
                s.sendall(b"\r\n")

            raw_banner = s.recv(512)
            banner = raw_banner.decode("utf-8", errors="ignore").strip()
            if banner:
                return banner.splitlines()[0][:60]
    except Exception:
        pass
    return ""


def fingerprint_os_from_ttl(ttl):
    """
    Estimates the operating system family based on the initial TTL value.
    Common initial TTLs:
      - Linux / Android / macOS / iOS: 64
      - Windows: 128
      - Network devices (Cisco, routers, Solaris): 255
    """
    if ttl is None or ttl <= 0:
        return "Unknown OS", 0

    if ttl <= 64:
        hops = 64 - ttl
        return "Linux / Unix / Apple", max(0, hops)
    elif ttl <= 128:
        hops = 128 - ttl
        return "Windows", max(0, hops)
    elif ttl <= 255:
        hops = 255 - ttl
        return "Network Device (Cisco/Solaris)", max(0, hops)
    return "Unknown OS", 0


# ==========================================
# Core Scanning Functions
# ==========================================

def arp_scan(ip, resolve_hostnames=True):
    """
    Performs a network scan by sending ARP requests to an IP address or range.

    Args:
        ip (str): An IP address or CIDR range (e.g. 192.168.1.1/24).
        resolve_hostnames (bool): Whether to resolve hostnames via reverse DNS.

    Returns:
        List of dictionaries with host information.
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    try:
        ans, unans = srp(request, timeout=2, retry=1, verbose=False)
    except PermissionError:
        raise PermissionError(
            "ARP scan requires raw socket privileges. Please run with sudo:\n"
            f"  sudo .venv/bin/python scanner.py ARP {ip}"
        )

    result = []
    for sent, received in ans:
        host_ip = received.psrc
        host_mac = received.hwsrc
        vendor = resolve_mac_vendor(host_mac)
        hostname = resolve_hostname(host_ip) if resolve_hostnames else ""

        # Check for tags
        tag_info = DeviceTagManager.get_tag(host_ip, host_mac)
        tag_label = tag_info["label"] if tag_info else ""
        tag_notes = tag_info["notes"] if tag_info else ""

        result.append({
            "IP": host_ip,
            "MAC": host_mac,
            "Vendor": vendor,
            "Hostname": hostname,
            "Label": tag_label,
            "Notes": tag_notes
        })

    return result


def execute_ping(target, count=2, timeout=1.0):
    """
    Sends ICMP echo requests using the system ping command.
    Captures reachability, packet loss, RTT stats, and TTL for OS fingerprinting.
    """
    cmd = ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), target]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 2)
        out = res.stdout
    except Exception:
        return {
            "alive": False,
            "loss_percent": 100.0,
            "rtt_avg": None,
            "rtt_min": None,
            "rtt_max": None,
            "jitter": None,
            "ttl": None,
            "os_guess": "Unknown",
            "hops": 0
        }

    # Extract packet loss
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out)
    loss = float(loss_match.group(1)) if loss_match else 100.0

    # Extract TTL
    ttl_match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
    ttl = int(ttl_match.group(1)) if ttl_match else None

    # Extract RTT min/avg/max/mdev
    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)",
        out
    )
    if rtt_match:
        rtt_min, rtt_avg, rtt_max, jitter = map(float, rtt_match.groups())
    else:
        rtt_min, rtt_avg, rtt_max, jitter = None, None, None, None

    os_guess, hops = fingerprint_os_from_ttl(ttl)

    return {
        "alive": res.returncode == 0 and loss < 100.0,
        "loss_percent": loss,
        "rtt_avg": rtt_avg,
        "rtt_min": rtt_min,
        "rtt_max": rtt_max,
        "jitter": jitter,
        "ttl": ttl,
        "os_guess": os_guess,
        "hops": hops
    }


def ping_sweep(network_cidr, max_workers=50, timeout=1.0):
    """
    Performs a multi-threaded ping sweep over a CIDR block.
    Returns list of discovered hosts and latency metrics.
    """
    net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()]

    active_hosts = []

    def probe(ip_str):
        p_res = execute_ping(ip_str, count=1, timeout=timeout)
        if p_res["alive"]:
            tag_info = DeviceTagManager.get_tag(ip_str)
            hostname = resolve_hostname(ip_str)
            return {
                "IP": ip_str,
                "Status": "ALIVE",
                "Latency": f"{p_res['rtt_avg']}ms" if p_res["rtt_avg"] else "<1ms",
                "TTL": p_res["ttl"] or "-",
                "OS_Guess": p_res["os_guess"],
                "Hops": p_res["hops"],
                "Hostname": hostname,
                "Label": tag_info["label"] if tag_info else "",
                "Notes": tag_info["notes"] if tag_info else ""
            }
        return None

    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts) or 1)) as executor:
        futures = {executor.submit(probe, ip): ip for ip in hosts}
        for future in as_completed(futures):
            res = future.result()
            if res:
                active_hosts.append(res)

    active_hosts.sort(key=lambda x: ipaddress.IPv4Address(x["IP"]))
    return active_hosts


def tcp_connect_scan(ip, ports, timeout=0.6, max_workers=50, grab_banners=True):
    """
    Performs a multi-threaded TCP connect scan.
    Does NOT require root or sudo privileges.
    """
    open_ports = []

    def probe(port):
        start_t = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                code = s.connect_ex((ip, port))
                latency_ms = (time.time() - start_t) * 1000.0
                if code == 0:
                    service = get_service_name(port)
                    banner = grab_banner(ip, port, timeout=0.8) if grab_banners else ""
                    warning = SECURITY_WARNINGS.get(port, "")
                    return {
                        "port": port,
                        "state": "OPEN",
                        "service": service,
                        "latency_ms": round(latency_ms, 1),
                        "banner": banner,
                        "warning": warning
                    }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as executor:
        futures = {executor.submit(probe, p): p for p in ports}
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def tcp_syn_scan(ip, ports):
    """
    Performs a raw TCP SYN scan (half-open).
    Captures TTL and fingerprints operating system.
    Requires root / sudo privileges.
    """
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError(f"Hostname {ip} could not be resolved.")

    try:
        ans, unans = sr(syn, timeout=2, retry=1, verbose=False)
    except PermissionError:
        raise PermissionError(
            "TCP SYN scan requires raw socket privileges. Please run with sudo or omit --syn for connect scan:\n"
            f"  sudo .venv/bin/python scanner.py TCP {ip} ..."
        )

    result = []
    for sent, received in ans:
        if received.haslayer(TCP) and received[TCP].flags == "SA":
            port = received[TCP].sport
            ttl = received[IP].ttl if received.haslayer(IP) else None
            os_guess, hops = fingerprint_os_from_ttl(ttl)
            result.append({
                "port": port,
                "state": "OPEN",
                "service": get_service_name(port),
                "latency_ms": 0.0,
                "ttl": ttl,
                "os_guess": os_guess,
                "banner": "",
                "warning": SECURITY_WARNINGS.get(port, "")
            })

    result.sort(key=lambda x: x["port"])
    return result


def tcp_scan(ip, ports):
    """
    Legacy wrapper for backwards-compatibility.
    Returns list of open port numbers.
    """
    results = tcp_connect_scan(ip, list(ports), grab_banners=False)
    return [r["port"] for r in results]


# ==========================================
# Reporting & Export Helpers (JSON / CSV / HTML)
# ==========================================

def generate_html_report(title, scan_type, target, stats, items, output_path="report.html"):
    """
    Generates a modern, standalone dark-themed HTML report.
    Requires zero external CDNs (100% offline-ready).
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build metric cards HTML
    cards_html = ""
    for label, val in stats.items():
        cards_html += f"""
        <div class="card">
            <div class="card-label">{html.escape(label)}</div>
            <div class="card-value">{html.escape(str(val))}</div>
        </div>
        """

    # Build table headers & rows
    table_headers_html = ""
    table_rows_html = ""

    if items:
        keys = list(items[0].keys())
        table_headers_html = "".join(f"<th>{html.escape(k)}</th>" for k in keys)

        for item in items:
            row_cells = ""
            for k in keys:
                val = str(item.get(k, "-") or "-")
                cell_class = ""
                badge_class = ""

                # Dynamic badge styles
                val_upper = val.upper()
                if "ONLINE" in val_upper or "ALIVE" in val_upper or "OPEN" in val_upper:
                    badge_class = "badge badge-online"
                elif "NEW" in val_upper:
                    badge_class = "badge badge-new"
                elif "OFFLINE" in val_upper:
                    badge_class = "badge badge-offline"
                elif "WARNING" in k.lower() and val != "-":
                    badge_class = "badge badge-warning"

                if badge_class:
                    content = f'<span class="{badge_class}">{html.escape(val)}</span>'
                else:
                    content = html.escape(val)

                row_cells += f"<td class='{cell_class}'>{content}</td>"
            table_rows_html += f"<tr>{row_cells}</tr>"
    else:
        table_headers_html = "<th>Status</th>"
        table_rows_html = "<tr><td>No records found.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)} - {html.escape(target)}</title>
    <style>
        :root {{
            --bg-body: #0b0f19;
            --bg-card: #151d2f;
            --bg-card-hover: #1c263c;
            --border-color: #243048;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #0ea5e9;
            --primary-glow: rgba(14, 165, 233, 0.2);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: var(--font-family);
            padding: 32px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 24px;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-title h1 {{
            font-size: 26px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .badge-type {{
            background: var(--primary-glow);
            color: var(--primary);
            border: 1px solid var(--primary);
            padding: 2px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .header-meta {{
            color: var(--text-muted);
            font-size: 13px;
            text-align: right;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            transition: transform 0.15s ease, background 0.15s ease;
        }}
        .card:hover {{
            background: var(--bg-card-hover);
        }}
        .card-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .card-value {{
            font-size: 24px;
            font-weight: 700;
            color: #ffffff;
        }}
        .table-container {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow-x: auto;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: #111827;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 11px;
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 14px 18px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            vertical-align: middle;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }}
        .badge-online {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-new {{ background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3); }}
        .badge-offline {{ background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }}
        .badge-warning {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            color: var(--text-muted);
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>{html.escape(title)} <span class="badge-type">{html.escape(scan_type)}</span></h1>
                <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Target: <strong>{html.escape(target)}</strong></p>
            </div>
            <div class="header-meta">
                <div>Generated: <strong>{timestamp}</strong></div>
                <div>Engine: <strong>Network Scanner Suite</strong></div>
            </div>
        </div>

        <div class="stats-grid">
            {cards_html}
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>{table_headers_html}</tr>
                </thead>
                <tbody>
                    {table_rows_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Network Scanner &bull; Automated Security & Discovery Audit
        </div>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Saved HTML report to: {output_path}")


def export_results(data, json_path=None, csv_path=None, html_path=None, report_meta=None):
    """Exports scan results to JSON, CSV, or standalone HTML."""
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved JSON report to: {json_path}")

    if csv_path and data:
        fieldnames = list(data[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        print(f"[+] Saved CSV report to: {csv_path}")

    if html_path and report_meta:
        generate_html_report(
            title=report_meta.get("title", "Network Scan Audit"),
            scan_type=report_meta.get("scan_type", "SCAN"),
            target=report_meta.get("target", "Target"),
            stats=report_meta.get("stats", {}),
            items=data,
            output_path=html_path
        )


# ==========================================
# CLI Handlers
# ==========================================

def print_banner():
    print(r"""
  _   _      _                      _      ____
 | \ | | ___| |___      _____  _ __| | __ / ___|  ___ __ _ _ __  _ __   ___ _ __
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <   ___) | (_| (_| | | | | | | |  __/ |
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|
    """)


def run_watch_loop(target_ip, interval=15, resolve_hostnames=True):
    """
    Monitors the network continuously.
    Alerts on new devices joining, devices disconnecting, or returning online.
    """
    print("\n" + "=" * 80)
    print(f"[*] Entering LIVE WATCH MODE on {target_ip}")
    print(f"[*] Check Interval: {interval} seconds | Press Ctrl+C to stop.")
    print("=" * 80)

    try:
        baseline = arp_scan(target_ip, resolve_hostnames=resolve_hostnames)
    except PermissionError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    seen = {d["IP"]: d for d in baseline}
    print(f"[*] [{datetime.now().strftime('%H:%M:%S')}] Baseline established: {len(seen)} active host(s).")
    for d in seen.values():
        name = d["Label"] or d["Hostname"] or "-"
        print(f"    • {d['IP']:<15} | {d['MAC']:<17} | {d['Vendor'][:20]:<20} | {name}")

    alerts_count = 0

    try:
        while True:
            time.sleep(interval)
            try:
                current = arp_scan(target_ip, resolve_hostnames=resolve_hostnames)
            except Exception as e:
                print(f"[!] Scan cycle error: {e}")
                continue

            now_str = datetime.now().strftime("%H:%M:%S")
            current_dict = {d["IP"]: d for d in current}

            # Check for new or returned devices
            for ip, d in current_dict.items():
                if ip not in seen:
                    alerts_count += 1
                    sys.stdout.write("\a")  # Audible terminal bell
                    sys.stdout.flush()
                    name = d["Label"] or d["Hostname"] or "Unknown"
                    print(f"\n[+] [ALERT - {now_str}] NEW DEVICE CONNECTED!")
                    print(f"    IP:       {ip}")
                    print(f"    MAC:      {d['MAC']} ({d['Vendor']})")
                    print(f"    Name:     {name}")
                    seen[ip] = d
                elif seen[ip].get("state") == "OFFLINE":
                    print(f"\n[~] [INFO - {now_str}] Device Returned Online: {ip} ({d['MAC']})")
                    seen[ip]["state"] = "ONLINE"

            # Check for disconnected devices
            for ip, d in list(seen.items()):
                if ip not in current_dict and d.get("state") != "OFFLINE":
                    d["state"] = "OFFLINE"
                    print(f"\n[-] [ALERT - {now_str}] Device Disconnected: {ip} ({d.get('MAC', 'Unknown')})")

    except KeyboardInterrupt:
        print("\n\n" + "=" * 80)
        print(f"[*] Watch mode terminated by user.")
        print(f"[*] Final Summary: Tracked {len(seen)} device(s) total | Alerts triggered: {alerts_count}")
        print("=" * 80)


def handle_arp(args):
    target = args.IP

    if args.local or not target:
        local_info = get_local_subnet()
        target = local_info["cidr"]
        print(f"[*] Auto-detected local subnet: {target} (Interface: {local_info['interface']}, Gateway: {local_info['gateway']})")

    if args.watch:
        interval = args.watch if isinstance(args.watch, int) and args.watch > 0 else 15
        run_watch_loop(target, interval=interval, resolve_hostnames=not args.no_resolve)
        return

    start_time = time.time()
    print(f"[*] Starting ARP scan on {target}...")

    try:
        current_devices = arp_scan(target, resolve_hostnames=not args.no_resolve)
    except PermissionError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    previous_devices = ScanHistoryManager.load_last_scan() if not args.no_history else {}
    current_ips = {d["IP"] for d in current_devices}

    # Annotate devices with state (NEW vs ONLINE)
    for d in current_devices:
        if d["IP"] in previous_devices:
            d["Status"] = "ONLINE"
        else:
            d["Status"] = "NEW"

    # Identify offline devices
    offline_devices = []
    if previous_devices:
        for ip, prev_info in previous_devices.items():
            if ip not in current_ips:
                offline_devices.append({
                    "IP": ip,
                    "MAC": prev_info.get("MAC", "Unknown"),
                    "Vendor": prev_info.get("Vendor", "Unknown"),
                    "Hostname": prev_info.get("Hostname", ""),
                    "Label": "",
                    "Notes": "",
                    "Status": "OFFLINE"
                })

    all_reported = current_devices + offline_devices
    duration = time.time() - start_time

    # Display Table
    print("\n" + "=" * 95)
    print(f"{'STATUS':<9} | {'IP ADDRESS':<16} | {'MAC ADDRESS':<18} | {'VENDOR':<22} | {'NAME / TAG'}")
    print("-" * 95)

    for d in current_devices:
        status_label = f"[{d['Status']}]"
        name_or_tag = d["Label"] or d["Hostname"] or "-"
        if d["Notes"]:
            name_or_tag += f" ({d['Notes']})"
        print(f"{status_label:<9} | {d['IP']:<16} | {d['MAC']:<18} | {d['Vendor'][:22]:<22} | {name_or_tag}")

    for d in offline_devices:
        print(f"[{'OFFLINE':<7}] | {d['IP']:<16} | {d['MAC']:<18} | {d['Vendor'][:22]:<22} | {d['Hostname'] or '-'}")

    print("=" * 95)
    print(f"[*] Scan finished in {duration:.2f}s | Active hosts: {len(current_devices)} | Offline: {len(offline_devices)}")

    if not args.no_history:
        ScanHistoryManager.save_scan(current_devices)

    meta = {
        "title": "Local Network ARP Audit",
        "scan_type": "ARP Discovery",
        "target": target,
        "stats": {
            "Total Discovered": len(all_reported),
            "Active Online": len(current_devices),
            "Offline Devices": len(offline_devices),
            "Scan Duration": f"{duration:.2f}s"
        }
    }
    export_results(all_reported, args.json, args.csv, args.html, report_meta=meta)


def handle_tcp(args):
    start_time = time.time()

    # Determine ports to scan
    if args.range:
        if len(args.ports) != 2:
            print("[!] Error: When using --range, specify exactly 2 ports: <low_port> <high_port>")
            sys.exit(1)
        low, high = min(args.ports), max(args.ports)
        target_ports = list(range(low, high + 1))
    elif args.top_ports:
        target_ports = COMMON_TOP_PORTS[:args.top_ports]
    elif args.ports:
        target_ports = args.ports
    else:
        target_ports = COMMON_TOP_PORTS

    method = "SYN Half-Open (Raw Socket)" if args.syn else "Connect Scan (Non-Root)"
    print(f"[*] Target: {args.IP} | Method: {method} | Ports to scan: {len(target_ports)}")

    # Check for device tag
    tag_info = DeviceTagManager.get_tag(args.IP)
    if tag_info:
        notes_str = f" ({tag_info['notes']})" if tag_info.get("notes") else ""
        print(f"[*] Device Label: {tag_info['label']}{notes_str}")

    try:
        if args.syn:
            results = tcp_syn_scan(args.IP, target_ports)
        else:
            results = tcp_connect_scan(
                args.IP,
                target_ports,
                timeout=args.timeout,
                max_workers=args.threads,
                grab_banners=not args.no_banner
            )
    except PermissionError as e:
        print(f"\n[!] {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    duration = time.time() - start_time

    # Display Table
    print("\n" + "=" * 80)
    print(f"{'PORT':<9} | {'STATE':<6} | {'SERVICE':<12} | {'LATENCY':<8} | {'BANNER / DETAILS'}")
    print("-" * 80)

    warnings_count = 0
    if not results:
        print("No open ports found.")
    else:
        for r in results:
            latency_str = f"{r['latency_ms']}ms" if r["latency_ms"] else "-"
            banner_str = r["banner"] if r["banner"] else "-"
            print(f"{r['port']:<9} | {r['state']:<6} | {r['service']:<12} | {latency_str:<8} | {banner_str}")
            if r.get("warning"):
                warnings_count += 1
                print(f"  └── ⚠ WARNING: {r['warning']}")

    print("=" * 80)
    print(f"[*] Scan finished in {duration:.2f}s | Open ports: {len(results)}/{len(target_ports)} | Security warnings: {warnings_count}")

    meta = {
        "title": "TCP Port Security Audit",
        "scan_type": "TCP Port Scan",
        "target": args.IP,
        "stats": {
            "Scanned Ports": len(target_ports),
            "Open Ports": len(results),
            "Security Flags": warnings_count,
            "Scan Duration": f"{duration:.2f}s"
        }
    }
    export_results(results, args.json, args.csv, args.html, report_meta=meta)


def handle_ping(args):
    target = args.target

    if args.local or not target:
        local_info = get_local_subnet()
        target = local_info["cidr"]
        print(f"[*] Auto-detected local subnet: {target} (Interface: {local_info['interface']}, Gateway: {local_info['gateway']})")

    # Detect if target is CIDR range or single host
    is_cidr = "/" in target
    start_time = time.time()

    if is_cidr:
        print(f"[*] Performing multi-threaded ping sweep across {target} (Threads: {args.threads})...")
        results = ping_sweep(target, max_workers=args.threads, timeout=args.timeout)
        duration = time.time() - start_time

        print("\n" + "=" * 90)
        print(f"{'IP ADDRESS':<16} | {'STATUS':<7} | {'LATENCY':<9} | {'TTL':<5} | {'ESTIMATED OS':<22} | {'NAME / TAG'}")
        print("-" * 90)

        for r in results:
            label = r["Label"] or r["Hostname"] or "-"
            print(f"{r['IP']:<16} | {r['Status']:<7} | {r['Latency']:<9} | {str(r['TTL']):<5} | {r['OS_Guess']:<22} | {label}")

        print("=" * 90)
        print(f"[*] Ping sweep completed in {duration:.2f}s | Responsive hosts: {len(results)}")

        meta = {
            "title": "ICMP Ping Sweep Audit",
            "scan_type": "Ping Sweep",
            "target": target,
            "stats": {
                "Active Hosts": len(results),
                "Threads": args.threads,
                "Duration": f"{duration:.2f}s"
            }
        }
        export_results(results, args.json, args.csv, args.html, report_meta=meta)

    else:
        print(f"[*] Pinging {target} ({args.count} packets, {args.timeout}s timeout)...")
        res = execute_ping(target, count=args.count, timeout=args.timeout)
        duration = time.time() - start_time

        tag_info = DeviceTagManager.get_tag(target)
        label = tag_info["label"] if tag_info else ""

        print("\n" + "=" * 60)
        print(f"Ping Results for: {target} {f'({label})' if label else ''}")
        print("-" * 60)
        if res["alive"]:
            print(f"Status:       [REACHABLE / ONLINE]")
            print(f"Latency:      min = {res['rtt_min']}ms | avg = {res['rtt_avg']}ms | max = {res['rtt_max']}ms")
            print(f"Jitter:       {res['jitter']}ms")
            print(f"Packet Loss:  {res['loss_percent']}%")
            print(f"TTL:          {res['ttl']} (Estimated Hops: {res['hops']})")
            print(f"OS Guess:     {res['os_guess']}")
        else:
            print(f"Status:       [UNREACHABLE / 100% PACKET LOSS]")
        print("=" * 60)

        report_data = [{
            "Target": target,
            "Status": "ONLINE" if res["alive"] else "OFFLINE",
            "Packet_Loss": f"{res['loss_percent']}%",
            "Avg_Latency": f"{res['rtt_avg']}ms" if res["rtt_avg"] else "-",
            "TTL": res["ttl"] or "-",
            "OS_Guess": res["os_guess"],
            "Label": label
        }]
        meta = {
            "title": f"Host Connectivity - {target}",
            "scan_type": "Ping Test",
            "target": target,
            "stats": {
                "Status": "ONLINE" if res["alive"] else "OFFLINE",
                "Packet Loss": f"{res['loss_percent']}%",
                "Latency": f"{res['rtt_avg']}ms" if res["rtt_avg"] else "-",
                "OS Guess": res["os_guess"]
            }
        }
        export_results(report_data, args.json, args.csv, args.html, report_meta=meta)


def handle_tag(args):
    if args.list:
        tags = DeviceTagManager.load_tags()
        if not tags:
            print("[*] No device tags configured.")
            return
        print("\n" + "=" * 65)
        print(f"{'TARGET (IP/MAC)':<20} | {'LABEL':<20} | {'NOTES'}")
        print("-" * 65)
        for target, info in tags.items():
            print(f"{target:<20} | {info['label']:<20} | {info.get('notes', '-')}")
        print("=" * 65)
    elif args.delete:
        if DeviceTagManager.delete_tag(args.delete):
            print(f"[+] Removed tag for {args.delete}")
        else:
            print(f"[!] No tag found for {args.delete}")
    elif args.target and args.label:
        DeviceTagManager.set_tag(args.target, args.label, args.notes or "")
        print(f"[+] Saved tag: {args.target} => '{args.label}' (Notes: {args.notes or 'None'})")
    else:
        print("[!] Specify a TARGET and LABEL, or use --list / --delete.")


def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner - ARP discovery, multi-threaded TCP/Ping scanner, OS detection, and network inventory."
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to perform.", required=True)

    # -----------------------------
    # ARP Subcommand
    # -----------------------------
    arp_parser = subparsers.add_parser("ARP", help="Perform ARP discovery on a local network.")
    arp_parser.add_argument("IP", nargs="?", help="An IP address or CIDR range. If omitted, pass --local.")
    arp_parser.add_argument("--local", action="store_true", help="Auto-detect local interface subnet and scan.")
    arp_parser.add_argument("--watch", type=int, nargs="?", const=15, metavar="SECONDS",
                            help="Run in continuous watch mode (default: 15s interval). Alerts on new devices.")
    arp_parser.add_argument("--no-resolve", action="store_true", help="Skip reverse DNS hostname resolution.")
    arp_parser.add_argument("--no-history", action="store_true", help="Do not compare or record scan history.")
    arp_parser.add_argument("--json", help="Export results to a JSON file.")
    arp_parser.add_argument("--csv", help="Export results to a CSV file.")
    arp_parser.add_argument("--html", help="Export a styled HTML security audit report.")

    # -----------------------------
    # TCP Subcommand
    # -----------------------------
    tcp_parser = subparsers.add_parser("TCP", help="Perform a TCP port scan.")
    tcp_parser.add_argument("IP", help="An IP address or hostname to target.")
    tcp_parser.add_argument(
        "ports", nargs="*", type=int, default=[],
        help="Specific ports to scan (e.g. 80 443 22). If empty and no --range/--top-ports, defaults to top 20 ports."
    )
    tcp_parser.add_argument(
        "--range", action="store_true",
        help="Scan a port range. Provide exactly 2 numbers in <ports>: <low_port> <high_port>."
    )
    tcp_parser.add_argument(
        "--top-ports", type=int, metavar="N",
        help="Scan top N common ports (up to 20)."
    )
    tcp_parser.add_argument(
        "--syn", action="store_true",
        help="Perform raw TCP SYN half-open scan (requires root/sudo). Default is standard TCP connect scan (no root)."
    )
    tcp_parser.add_argument(
        "--timeout", type=float, default=0.6,
        help="Socket connection timeout in seconds (default: 0.6)."
    )
    tcp_parser.add_argument(
        "--threads", type=int, default=50,
        help="Number of concurrent threads (default: 50)."
    )
    tcp_parser.add_argument(
        "--no-banner", action="store_true",
        help="Skip service banner grabbing."
    )
    tcp_parser.add_argument("--json", help="Export results to a JSON file.")
    tcp_parser.add_argument("--csv", help="Export results to a CSV file.")
    tcp_parser.add_argument("--html", help="Export a styled HTML security audit report.")

    # -----------------------------
    # PING Subcommand
    # -----------------------------
    ping_parser = subparsers.add_parser("PING", help="Check host reachability, latency, packet loss, and OS fingerprint.")
    ping_parser.add_argument("target", nargs="?", help="Target IP, hostname, or CIDR range (e.g. 192.168.1.1 or 192.168.1.0/24).")
    ping_parser.add_argument("--local", action="store_true", help="Auto-detect local subnet and run a multi-threaded ping sweep.")
    ping_parser.add_argument("--count", "-c", type=int, default=4, help="Number of ping packets to send (single host, default: 4).")
    ping_parser.add_argument("--timeout", "-W", type=float, default=1.0, help="Timeout in seconds for ping responses (default: 1.0s).")
    ping_parser.add_argument("--threads", type=int, default=50, help="Threads for ping sweep across CIDR ranges (default: 50).")
    ping_parser.add_argument("--json", help="Export results to a JSON file.")
    ping_parser.add_argument("--csv", help="Export results to a CSV file.")
    ping_parser.add_argument("--html", help="Export a styled HTML security audit report.")

    # -----------------------------
    # TAG Subcommand
    # -----------------------------
    tag_parser = subparsers.add_parser("TAG", help="Manage labels and notes for network devices.")
    tag_parser.add_argument("target", nargs="?", help="IP address or MAC address to tag.")
    tag_parser.add_argument("label", nargs="?", help="Friendly name / label (e.g. 'Main Router', 'Office Printer').")
    tag_parser.add_argument("--notes", help="Optional detailed notes.")
    tag_parser.add_argument("--list", action="store_true", help="List all saved device tags.")
    tag_parser.add_argument("--delete", help="Delete the tag for the given IP or MAC.")

    args = parser.parse_args()

    if args.command == "ARP":
        handle_arp(args)
    elif args.command == "TCP":
        handle_tcp(args)
    elif args.command == "PING":
        handle_ping(args)
    elif args.command == "TAG":
        handle_tag(args)


if __name__ == "__main__":
    main()
