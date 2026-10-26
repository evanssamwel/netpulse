"""
Wireless / Wi-Fi Network Discovery and Security Audit Scanner for Linux.
Discovers nearby Access Points (SSIDs, BSSIDs, Channels, Signal Strength, and Encryption).
Flags open or insecure wireless networks (WEP / Open).
"""

import os
import re
import shutil
import subprocess


def get_wireless_interfaces():
    """
    Detects available wireless interfaces on Linux systems.
    Inspects /sys/class/net and /proc/net/wireless.
    """
    ifaces = []
    # Check /sys/class/net/*/wireless
    net_dir = "/sys/class/net"
    if os.path.exists(net_dir):
        for name in os.listdir(net_dir):
            if os.path.exists(os.path.join(net_dir, name, "wireless")) or name.startswith(("wl", "wlan", "wifi")):
                ifaces.append(name)

    # Check /proc/net/wireless
    if os.path.exists("/proc/net/wireless"):
        try:
            with open("/proc/net/wireless", "r") as f:
                for line in f:
                    if ":" in line:
                        iface = line.split(":")[0].strip()
                        if iface and iface not in ifaces:
                            ifaces.append(iface)
        except Exception:
            pass

    return sorted(list(set(ifaces)))


def _format_signal_bar(pct):
    """Generates visual signal strength bar."""
    try:
        val = int(pct)
    except (ValueError, TypeError):
        return "[    ]"
    
    if val >= 75:
        return "[████]"
    elif val >= 50:
        return "[███ ]"
    elif val >= 25:
        return "[██  ]"
    elif val > 0:
        return "[█   ]"
    return "[    ]"


def scan_wifi(interface=None, timeout=10):
    """
    Scans for nearby wireless access points.
    Attempts nmcli first, followed by iw / iwlist if available.

    Returns:
        dict: {
            "status": "success" | "error",
            "interface": str,
            "networks": list of dicts,
            "warnings": list of str
        }
    """
    results = []
    warnings = []
    
    # 1. Attempt nmcli scan (NetworkManager)
    if shutil.which("nmcli"):
        try:
            cmd = ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"]
            if interface:
                cmd.extend(["ifname", interface])
            
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            if proc.returncode == 0 and proc.stdout.strip():
                seen_bssids = set()
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    # nmcli colon escaping format: colons in BSSID can be escaped or raw
                    # Format: SSID:BSSID:CHAN:SIGNAL:SECURITY
                    parts = line.split(":")
                    if len(parts) >= 5:
                        # BSSID is 6 hex bytes with colons, so parts could be split differently
                        # Better regex split for unescaped colons
                        bssid_match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
                        if bssid_match:
                            bssid = bssid_match.group(1)
                            before_bssid = line[:bssid_match.start()].rstrip(":")
                            after_bssid = line[bssid_match.end():].lstrip(":")
                            
                            ssid = before_bssid.replace("\\:", ":").strip() or "<Hidden SSID>"
                            rest_parts = after_bssid.split(":")
                            channel = rest_parts[0].strip() if len(rest_parts) > 0 else "?"
                            signal_str = rest_parts[1].strip() if len(rest_parts) > 1 else "0"
                            security = ":".join(rest_parts[2:]).strip() if len(rest_parts) > 2 else "OPEN"
                            if not security:
                                security = "OPEN"
                            
                            if bssid in seen_bssids:
                                continue
                            seen_bssids.add(bssid)
                            
                            try:
                                signal_int = int(signal_str)
                            except ValueError:
                                signal_int = 0
                            
                            is_open = security.upper() in ("OPEN", "--", "NONE", "")
                            is_wep = "WEP" in security.upper()
                            
                            item = {
                                "ssid": ssid,
                                "bssid": bssid,
                                "channel": channel,
                                "signal": signal_int,
                                "security": security,
                                "is_insecure": is_open or is_wep,
                                "risk_label": "CRITICAL" if is_wep else ("WARNING" if is_open else "CLEAN")
                            }
                            if is_open:
                                warnings.append(f"Open / Unencrypted Wi-Fi network detected: '{ssid}' ({bssid})")
                            elif is_wep:
                                warnings.append(f"Deprecated WEP encryption detected on '{ssid}' ({bssid}) - Vulnerable to IV injection!")
                            
                            results.append(item)
                
                if results:
                    results.sort(key=lambda x: x["signal"], reverse=True)
                    return {
                        "status": "success",
                        "method": "nmcli",
                        "interface": interface or "default",
                        "networks": results,
                        "warnings": warnings
                    }
        except Exception:
            pass

    # 2. Fallback to iw / iwlist
    ifaces = [interface] if interface else get_wireless_interfaces()
    if not ifaces:
        return {
            "status": "error",
            "message": "No wireless network interfaces detected on this system.",
            "networks": [],
            "warnings": []
        }

    target_iface = ifaces[0]
    if shutil.which("iwlist"):
        try:
            cmd = ["iwlist", target_iface, "scan"]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            if proc.returncode == 0:
                current_cell = {}
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Cell "):
                        if current_cell.get("bssid"):
                            results.append(current_cell)
                        b_match = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
                        current_cell = {
                            "bssid": b_match.group(1) if b_match else "Unknown",
                            "ssid": "<Hidden SSID>",
                            "channel": "?",
                            "signal": 50,
                            "security": "OPEN",
                            "is_insecure": True,
                            "risk_label": "WARNING"
                        }
                    elif line.startswith("ESSID:"):
                        ssid = line.split("ESSID:")[1].strip().strip('"')
                        current_cell["ssid"] = ssid if ssid else "<Hidden SSID>"
                    elif "Channel:" in line:
                        ch = re.search(r"Channel:(\d+)", line)
                        if ch:
                            current_cell["channel"] = ch.group(1)
                    elif "Quality=" in line:
                        qual = re.search(r"Quality=(\d+)/(\d+)", line)
                        if qual:
                            pct = int((int(qual.group(1)) / int(qual.group(2))) * 100)
                            current_cell["signal"] = pct
                    elif "Encryption key:off" in line:
                        current_cell["security"] = "OPEN"
                        current_cell["is_insecure"] = True
                        current_cell["risk_label"] = "WARNING"
                    elif "IEEE 802.11i/WPA2" in line or "WPA2" in line:
                        current_cell["security"] = "WPA2"
                        current_cell["is_insecure"] = False
                        current_cell["risk_label"] = "CLEAN"
                    elif "WPA Version 1" in line:
                        current_cell["security"] = "WPA1"
                        current_cell["is_insecure"] = True
                        current_cell["risk_label"] = "WARNING"

                if current_cell.get("bssid"):
                    results.append(current_cell)

                if results:
                    results.sort(key=lambda x: x["signal"], reverse=True)
                    for net in results:
                        if net.get("is_insecure"):
                            sec = net.get("security", "")
                            if "WEP" in sec.upper():
                                warnings.append(f"Deprecated WEP encryption detected on '{net['ssid']}' ({net['bssid']}) - Insecure!")
                            elif sec.upper() in ("OPEN", "--", "NONE", ""):
                                warnings.append(f"Open / Unencrypted Wi-Fi network detected: '{net['ssid']}' ({net['bssid']})")
                    return {
                        "status": "success",
                        "method": "iwlist",
                        "interface": target_iface,
                        "networks": results,
                        "warnings": warnings
                    }
        except Exception:
            pass

    return {
        "status": "error",
        "message": f"Wireless scan failed. Ensure wireless interface ('{target_iface}') is powered on or run with sudo.",
        "networks": [],
        "warnings": []
    }


def print_wifi_results(scan_data):
    """Prints a styled terminal table of wireless discovery findings."""
    networks = scan_data.get("networks", [])
    if not networks:
        print(f"\n[!] No wireless networks found. {scan_data.get('message', '')}")
        return

    print("\n" + "=" * 80)
    print(f"  WIRELESS / WI-FI RECONNAISSANCE AUDIT ({len(networks)} Access Points Found)")
    print("=" * 80)
    print(f"  {'SSID':<26} {'BSSID':<18} {'CHAN':<6} {'SIGNAL':<14} {'SECURITY':<14}")
    print("-" * 80)

    for net in networks:
        ssid = net["ssid"]
        if len(ssid) > 24:
            ssid = ssid[:21] + "..."
        bssid = net["bssid"]
        chan = net["channel"]
        signal = f"{net['signal']}% {_format_signal_bar(net['signal'])}"
        sec = net["security"]
        
        # Color or highlight insecure networks
        if net.get("is_insecure"):
            sec = f"{sec} [!]"

        print(f"  {ssid:<26} {bssid:<18} {chan:<6} {signal:<14} {sec:<14}")

    warnings = scan_data.get("warnings", [])
    if warnings:
        print("\n" + "!" * 80)
        print("  WIRELESS SECURITY WARNINGS & RISKS:")
        for w in warnings:
            print(f"  - {w}")
        print("!" * 80)
    else:
        print("\n  [✓] All detected wireless networks have encryption enabled.")
    print("=" * 80 + "\n")
