"""
Layer 2 ARP Discovery & Continuous Live Watch Mode.
Performs rapid local host discovery, hardware OUI vendor identification,
device classification, and continuous real-time intrusion/disconnection alerts.
"""

import sys
import time
from datetime import datetime
from network_scanner.fingerprint.device_type import classify_device
from network_scanner.inventory.tags import DeviceTagManager
from network_scanner.utils.network import resolve_hostname, resolve_mac_vendor

# Scapy Layer 2 imports
from scapy.all import ARP, Ether, srp


def arp_scan(ip, resolve_hostnames=True, gateway_ip=None):
    """
    Performs a network scan by sending ARP requests to an IP address or range.

    Args:
        ip (str): An IP address or CIDR range (e.g. 192.168.1.1/24).
        resolve_hostnames (bool): Whether to resolve hostnames via reverse DNS.
        gateway_ip (str): IP address of default gateway for role tagging.

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

        is_gw = (gateway_ip and host_ip == gateway_ip)
        device_type, confidence, details = classify_device(
            ip=host_ip,
            mac=host_mac,
            vendor=vendor,
            hostname=hostname,
            is_gateway=is_gw
        )

        result.append({
            "IP": host_ip,
            "MAC": host_mac,
            "Vendor": vendor,
            "Hostname": hostname,
            "DeviceType": device_type,
            "ProfileDetails": details,
            "Label": tag_label,
            "Notes": tag_notes
        })

    return result


def run_watch_loop(target_ip, interval=15, resolve_hostnames=True, webhook_url=None):
    """
    Monitors the network continuously.
    Alerts on new devices joining, devices disconnecting, or returning online.
    Optionally dispatches alerts via webhook (Discord / Slack).
    """
    from network_scanner.core.notifications import send_webhook_alert

    print("\n" + "=" * 80)
    print(f"[*] Entering LIVE WATCH MODE on {target_ip}")
    print(f"[*] Check Interval: {interval} seconds | Press Ctrl+C to stop.")
    if webhook_url:
        print(f"[*] Webhook alerts enabled: {webhook_url[:35]}...")
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
        dtype = f"[{d.get('DeviceType', 'Device')}]"
        print(f"    • {d['IP']:<15} | {d['MAC']:<17} | {d['Vendor'][:18]:<18} | {dtype:<16} | {name}")

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
                    dtype = d.get("DeviceType", "Device")
                    print(f"\n[+] [ALERT - {now_str}] NEW DEVICE CONNECTED!")
                    print(f"    IP:       {ip}")
                    print(f"    MAC:      {d['MAC']} ({d['Vendor']})")
                    print(f"    Role:     {dtype}")
                    print(f"    Name:     {name}")
                    seen[ip] = d

                    if webhook_url:
                        send_webhook_alert(
                            webhook_url,
                            title="New Device Connected",
                            message=f"New device `{ip}` joined the network.",
                            fields={
                                "IP Address": ip,
                                "MAC Address": d.get("MAC", "Unknown"),
                                "Vendor": d.get("Vendor", "Unknown"),
                                "Device Role": dtype,
                                "Hostname": name
                            },
                            severity="WARNING"
                        )
                elif seen[ip].get("state") == "OFFLINE":
                    print(f"\n[~] [INFO - {now_str}] Device Returned Online: {ip} ({d['MAC']})")
                    seen[ip]["state"] = "ONLINE"

            # Check for disconnected devices
            for ip, d in list(seen.items()):
                if ip not in current_dict and d.get("state") != "OFFLINE":
                    d["state"] = "OFFLINE"
                    print(f"\n[-] [ALERT - {now_str}] Device Disconnected: {ip} ({d.get('MAC', 'Unknown')})")
                    if webhook_url:
                        send_webhook_alert(
                            webhook_url,
                            title="Device Disconnected",
                            message=f"Device `{ip}` has gone offline.",
                            fields={"IP Address": ip, "MAC": d.get("MAC", "Unknown")},
                            severity="INFO"
                        )

    except KeyboardInterrupt:
        print("\n\n" + "=" * 80)
        print(f"[*] Watch mode terminated by user.")
        print(f"[*] Final Summary: Tracked {len(seen)} device(s) total | Alerts triggered: {alerts_count}")
        print("=" * 80)
