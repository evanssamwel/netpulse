#!/usr/bin/env python3
"""
Network Scanner Suite (v2.3.0)
Advanced Network Discovery, Security Auditing, and Asset Inventory Toolkit.
"""

import argparse
import sys
import time

# Internal modular imports
from network_scanner import __version__
from network_scanner.constants import COMMON_TOP_PORTS, COMMON_UDP_PORTS
from network_scanner.core.config import load_config, save_config
from network_scanner.fingerprint.device_type import classify_device
from network_scanner.fingerprint.services import grab_banner
from network_scanner.fingerprint.ttl import fingerprint_os_from_ttl
from network_scanner.inventory.history import ScanHistoryManager
from network_scanner.inventory.tags import DeviceTagManager
from network_scanner.reports.export import export_results
from network_scanner.reports.html_report import generate_html_report
from network_scanner.reports.topology import export_topology_svg, generate_topology_svg
from network_scanner.scanners.arp import arp_scan, run_watch_loop
from network_scanner.scanners.dns import enumerate_domain_dns, test_axfr_zone_transfer
from network_scanner.scanners.ping import execute_ping, ping_sweep
from network_scanner.scanners.smb import enumerate_smb
from network_scanner.scanners.sniff import run_packet_sniffer
from network_scanner.scanners.snmp import enumerate_snmp
from network_scanner.scanners.tcp import tcp_connect_scan, tcp_scan, tcp_syn_scan
from network_scanner.scanners.udp import udp_scan
from network_scanner.scanners.wifi import print_wifi_results, scan_wifi
from network_scanner.security.cve import audit_host_vulnerabilities, lookup_cves
from network_scanner.security.risk import calculate_host_risk, calculate_network_risk
from network_scanner.server.api import start_server
from network_scanner.utils.geo import format_geo_banner, get_ip_geolocation, is_public_ip
from network_scanner.utils.network import (
    get_local_subnet,
    get_service_name,
    int2ip,
    resolve_hostname,
    resolve_mac_vendor,
)


def print_banner():
    print(r"""
  _   _      _                      _      ____
 | \ | | ___| |___      _____  _ __| | __ / ___|  ___ __ _ _ __  _ __   ___ _ __
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <   ___) | (_| (_| | | | | | | |  __/ |
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|  v2.3
    """)


def handle_arp(args):
    target = args.IP
    gateway_ip = None
    config = load_config()

    if args.local or not target:
        local_info = get_local_subnet()
        target = local_info["cidr"]
        gateway_ip = local_info.get("gateway")
        print(f"[*] Auto-detected local subnet: {target} (Interface: {local_info['interface']}, Gateway: {gateway_ip})")

    webhook_url = args.webhook or config.get("webhook_url")

    if args.watch:
        interval = args.watch if isinstance(args.watch, int) and args.watch > 0 else config.get("watch_interval", 15)
        run_watch_loop(target, interval=interval, resolve_hostnames=not args.no_resolve, webhook_url=webhook_url)
        return

    start_time = time.time()
    print(f"[*] Starting ARP scan on {target}...")

    try:
        current_devices = arp_scan(target, resolve_hostnames=not args.no_resolve, gateway_ip=gateway_ip)
    except PermissionError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    # Perform history diffing and change detection
    if not args.no_history:
        diff_res = ScanHistoryManager.diff_scan(current_devices)
        all_reported = current_devices + diff_res["offline"]
        changes = diff_res["changes"]
    else:
        for d in current_devices:
            d["Status"] = "ONLINE"
        all_reported = current_devices
        changes = []

    duration = time.time() - start_time

    # Display Table
    print("\n" + "=" * 105)
    print(f"{'STATUS':<9} | {'IP ADDRESS':<16} | {'MAC ADDRESS':<18} | {'VENDOR':<20} | {'DEVICE ROLE':<20} | {'NAME / TAG'}")
    print("-" * 105)

    for d in current_devices:
        status_label = f"[{d.get('Status', 'ONLINE')}]"
        name_or_tag = d["Label"] or d["Hostname"] or "-"
        if d.get("Notes"):
            name_or_tag += f" ({d['Notes']})"
        role_str = d.get("DeviceType", "Device")
        print(f"{status_label:<9} | {d['IP']:<16} | {d['MAC']:<18} | {d['Vendor'][:20]:<20} | {role_str[:20]:<20} | {name_or_tag}")

    offline_count = 0
    if not args.no_history:
        for d in diff_res["offline"]:
            offline_count += 1
            name_str = d.get("Hostname") or "-"
            role_str = d.get("DeviceType", "Device")
            print(f"[{'OFFLINE':<7}] | {d['IP']:<16} | {d['MAC']:<18} | {d['Vendor'][:20]:<20} | {role_str[:20]:<20} | {name_str}")

    print("=" * 105)
    print(f"[*] Scan finished in {duration:.2f}s | Active online: {len(current_devices)} | Known offline: {offline_count}")

    if changes:
        print("\n[*] Detected Network Diffs & Change Log:")
        for ch in changes[:10]:
            print(f"    • {ch}")

    if not args.no_history:
        ScanHistoryManager.record_scan(current_devices)

    meta = {
        "title": "Local Network Discovery & Asset Inventory",
        "scan_type": "ARP Discovery",
        "target": target,
        "gateway_ip": gateway_ip,
        "stats": {
            "Total Tracked": len(all_reported),
            "Active Online": len(current_devices),
            "Offline Hosts": offline_count,
            "Scan Duration": f"{duration:.2f}s"
        }
    }
    export_results(all_reported, args.json, args.csv, args.html, svg_path=args.svg, report_meta=meta, theme=getattr(args, "theme", None))


def handle_tcp(args):
    start_time = time.time()
    config = load_config()

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
    timeout = args.timeout or config.get("timeout", 0.6)
    threads = args.threads or config.get("threads", 50)
    print(f"[*] Target: {args.IP} | Method: {method} | Ports to scan: {len(target_ports)}")

    # Display WAN GeoIP intelligence for public IPs
    if is_public_ip(args.IP):
        geo = get_ip_geolocation(args.IP)
        if geo.get("status") == "success":
            print(format_geo_banner(geo))

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
                timeout=timeout,
                max_workers=threads,
                grab_banners=not args.no_banner
            )
    except PermissionError as e:
        print(f"\n[!] {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    duration = time.time() - start_time

    risk_info = calculate_host_risk(results)
    cve_info = audit_host_vulnerabilities(results)

    # Display Table
    print("\n" + "=" * 90)
    print(f"{'PORT':<9} | {'STATE':<6} | {'SERVICE':<12} | {'LATENCY':<8} | {'VERSION / BANNER / DETAILS'}")
    print("-" * 90)

    warnings_count = 0
    if not results:
        print("No open ports found.")
    else:
        for r in results:
            latency_str = f"{r['latency_ms']}ms" if r["latency_ms"] else "-"
            banner_str = r.get("version") or r.get("banner") or "-"
            print(f"{r['port']:<9} | {r['state']:<6} | {r['service']:<12} | {latency_str:<8} | {banner_str}")
            if r.get("warning"):
                warnings_count += 1
                print(f"  └── ⚠ WARNING: {r['warning']}")

    print("=" * 90)
    print(f"[*] Scan finished in {duration:.2f}s | Open ports: {len(results)}/{len(target_ports)}")
    print(f"[*] Security Posture Score: {risk_info['score']}/100 [{risk_info['level']}] | Security Flags: {warnings_count}")

    if cve_info["cves"]:
        print(f"\n[!] VULNERABILITIES DETECTED ({len(cve_info['cves'])}):")
        for c in cve_info["cves"]:
            print(f"  └── 🔴 [{c['cve']}] {c['title']} (CVSS {c.get('cvss', 'N/A')} - {c['severity']})")
            print(f"      Remediation: {c['remediation']}")

    if risk_info["recommendations"]:
        print("\n[*] Recommended Remediations:")
        for rec in risk_info["recommendations"]:
            print(f"    • {rec}")

    meta = {
        "title": "TCP Port Security Audit",
        "scan_type": "TCP Port Scan",
        "target": args.IP,
        "stats": {
            "Scanned Ports": len(target_ports),
            "Open Ports": len(results),
            "Security Score": f"{risk_info['score']}/100 ({risk_info['level']})",
            "Known CVEs": len(cve_info["cves"]),
            "Security Flags": warnings_count,
            "Scan Duration": f"{duration:.2f}s"
        }
    }
    export_results(results, args.json, args.csv, args.html, report_meta=meta, risk_data=risk_info, cve_data=cve_info, theme=getattr(args, "theme", None))


def handle_udp(args):
    start_time = time.time()
    config = load_config()

    if args.range:
        if len(args.ports) != 2:
            print("[!] Error: When using --range, specify exactly 2 ports: <low_port> <high_port>")
            sys.exit(1)
        low, high = min(args.ports), max(args.ports)
        target_ports = list(range(low, high + 1))
    elif args.top_ports:
        target_ports = COMMON_UDP_PORTS[:args.top_ports]
    elif args.ports:
        target_ports = args.ports
    else:
        target_ports = COMMON_UDP_PORTS

    timeout = args.timeout or config.get("udp_timeout", 1.5)
    threads = args.threads or 30
    print(f"[*] Target: {args.IP} | Method: UDP Probe Scan | Ports to scan: {len(target_ports)}")

    # Display WAN GeoIP intelligence for public IPs
    if is_public_ip(args.IP):
        geo = get_ip_geolocation(args.IP)
        if geo.get("status") == "success":
            print(format_geo_banner(geo))

    tag_info = DeviceTagManager.get_tag(args.IP)
    if tag_info:
        notes_str = f" ({tag_info['notes']})" if tag_info.get("notes") else ""
        print(f"[*] Device Label: {tag_info['label']}{notes_str}")

    results = udp_scan(args.IP, target_ports, timeout=timeout, max_workers=threads)
    duration = time.time() - start_time

    risk_info = calculate_host_risk(results)
    cve_info = audit_host_vulnerabilities(results)

    # Display Table
    print("\n" + "=" * 85)
    print(f"{'PORT':<9} | {'STATE':<6} | {'SERVICE':<12} | {'LATENCY':<8} | {'SERVICE DETAILS'}")
    print("-" * 85)

    warnings_count = 0
    if not results:
        print("No responsive UDP ports found.")
    else:
        for r in results:
            latency_str = f"{r['latency_ms']}ms" if r["latency_ms"] else "-"
            banner_str = r.get("banner", "-")
            print(f"{r['port']:<9} | {r['state']:<6} | {r['service']:<12} | {latency_str:<8} | {banner_str}")
            if r.get("warning"):
                warnings_count += 1
                print(f"  └── ⚠ WARNING: {r['warning']}")

    print("=" * 85)
    print(f"[*] UDP scan finished in {duration:.2f}s | Responsive ports: {len(results)}/{len(target_ports)}")
    print(f"[*] Security Posture Score: {risk_info['score']}/100 [{risk_info['level']}] | Security Flags: {warnings_count}")

    if cve_info["cves"]:
        print(f"\n[!] VULNERABILITIES DETECTED ({len(cve_info['cves'])}):")
        for c in cve_info["cves"]:
            print(f"  └── 🔴 [{c['cve']}] {c['title']} (CVSS {c.get('cvss', 'N/A')} - {c['severity']})")
            print(f"      Remediation: {c['remediation']}")

    if risk_info["recommendations"]:
        print("\n[*] Recommended Remediations:")
        for rec in risk_info["recommendations"]:
            print(f"    • {rec}")

    meta = {
        "title": "UDP Service Discovery Audit",
        "scan_type": "UDP Port Scan",
        "target": args.IP,
        "stats": {
            "Scanned Ports": len(target_ports),
            "Responsive Ports": len(results),
            "Security Score": f"{risk_info['score']}/100 ({risk_info['level']})",
            "Security Flags": warnings_count,
            "Scan Duration": f"{duration:.2f}s"
        }
    }
    export_results(results, args.json, args.csv, args.html, report_meta=meta, risk_data=risk_info, cve_data=cve_info, theme=getattr(args, "theme", None))


def handle_snmp(args):
    print(f"[*] Initiating SNMP Enumeration against {args.IP}:{args.port}...")
    config = load_config()
    communities = [args.community] if args.community else config.get("snmp_communities", ["public", "private"])

    start_time = time.time()
    info = enumerate_snmp(args.IP, communities=communities, port=args.port, timeout=args.timeout)
    duration = time.time() - start_time

    if not info:
        print("[-] Target did not respond to SNMP GetRequest probes (port closed or non-standard community).")
        return

    print("\n" + "=" * 70)
    print(f"SNMP MIB-II Enumeration for: {args.IP}")
    print("-" * 70)
    print(f"Accepted Community: {info.get('community', 'public')}")
    print(f"System Description: {info.get('sysDescr', '-')}")
    print(f"System Name:        {info.get('sysName', '-')}")
    print(f"System Uptime:      {info.get('sysUpTime', '-')}")
    print(f"System Contact:     {info.get('sysContact', '-')}")
    print(f"System Location:    {info.get('sysLocation', '-')}")
    print("=" * 70)

    report_items = [{
        "Property": k,
        "Value": str(v)
    } for k, v in info.items()]

    meta = {
        "title": f"SNMP System Enumeration - {args.IP}",
        "scan_type": "SNMP Audit",
        "target": args.IP,
        "stats": {
            "Community": info.get("community"),
            "System Name": info.get("sysName", "Unknown"),
            "Uptime": info.get("sysUpTime", "N/A"),
            "Duration": f"{duration:.2f}s"
        }
    }
    export_results(report_items, args.json, args.csv, args.html, report_meta=meta, theme=getattr(args, "theme", None))


def handle_smb(args):
    print(f"[*] Initiating SMB Negotiation & Security Audit on {args.IP}:{args.port}...")
    start_time = time.time()
    info = enumerate_smb(args.IP, port=args.port, timeout=args.timeout)
    duration = time.time() - start_time

    if not info:
        print("[-] Target did not respond to SMB negotiation probes (port 445 closed or firewalled).")
        return

    print("\n" + "=" * 75)
    print(f"SMB Security & Protocol Audit for: {args.IP}")
    print("-" * 75)
    print(f"Dialect Negotiated: {info['selected_dialect']}")
    print(f"SMBv1 Status:       {'[CRITICAL - ENABLED]' if info['smbv1_enabled'] else '[SAFE - DISABLED]'}")
    print(f"Message Signing:    {'[ENFORCED / SECURE]' if info['signing_required'] else '[DISABLED / RELAY VULNERABLE]'}")
    if info.get("netbios_computer"):
        print(f"Computer Name:      {info['netbios_computer']} ({info.get('dns_computer', '')})")
    if info.get("netbios_domain"):
        print(f"Domain / Workgroup: {info['netbios_domain']} ({info.get('dns_domain', '')})")

    if info["warnings"]:
        print("\n[!] Security Warnings:")
        for w in info["warnings"]:
            print(f"  └── ⚠ {w}")

    print("=" * 75)

    risk_ports = [445]
    if info["smbv1_enabled"]:
        risk_ports.append(23)
    risk_info = calculate_host_risk(risk_ports)

    cve_data = {"cves": []}
    if info["smbv1_enabled"]:
        cve_matches = lookup_cves("SMB", "smbv1")
        cve_data["cves"].extend(cve_matches)

    report_items = [{
        "Attribute": "Dialect",
        "Value": info["selected_dialect"]
    }, {
        "Attribute": "SMBv1_Active",
        "Value": str(info["smbv1_enabled"])
    }, {
        "Attribute": "Signing_Required",
        "Value": str(info["signing_required"])
    }, {
        "Attribute": "Computer_Name",
        "Value": info.get("netbios_computer", "-")
    }, {
        "Attribute": "Domain_Name",
        "Value": info.get("netbios_domain", "-")
    }]

    meta = {
        "title": f"SMB Protocol Security Audit - {args.IP}",
        "scan_type": "SMB Audit",
        "target": args.IP,
        "stats": {
            "Dialect": info["selected_dialect"],
            "SMBv1": "Active" if info["smbv1_enabled"] else "Disabled",
            "Signing": "Required" if info["signing_required"] else "Vulnerable",
            "Duration": f"{duration:.2f}s"
        }
    }
    export_results(report_items, args.json, args.csv, args.html, report_meta=meta, risk_data=risk_info, cve_data=cve_data, theme=getattr(args, "theme", None))


def handle_dns(args):
    print(f"[*] Performing DNS Enumeration for: {args.target}...")
    start_time = time.time()
    dns_res = enumerate_domain_dns(args.target, custom_server=args.server, timeout=args.timeout)
    duration = time.time() - start_time

    print("\n" + "=" * 75)
    print(f"DNS Reconnaissance for: {args.target}")
    print("-" * 75)

    if dns_res["nameservers"]:
        print(f"Nameservers (NS):  {', '.join(dns_res['nameservers'])}")

    for rtype, values in dns_res["records"].items():
        print(f"{rtype:<16}   {', '.join(values)}")

    if dns_res["axfr_vulnerable"]:
        print("\n[!] CRITICAL ALERT: AXFR Zone Transfer is PERMITTED on authoritative nameservers!")
        for w in dns_res["warnings"]:
            print(f"  └── 🔴 {w}")
    else:
        print("[*] Zone Transfer (AXFR): Protected (Refused / Reflected)")

    print("=" * 75)
    print(f"[*] DNS audit finished in {duration:.2f}s")

    report_items = []
    for rtype, values in dns_res["records"].items():
        for val in values:
            report_items.append({"Record_Type": rtype, "Value": val})

    meta = {
        "title": f"DNS Reconnaissance - {args.target}",
        "scan_type": "DNS Enumeration",
        "target": args.target,
        "stats": {
            "Nameservers": len(dns_res["nameservers"]),
            "Records Found": len(report_items),
            "Zone Transfer": "VULNERABLE" if dns_res["axfr_vulnerable"] else "Secure",
            "Duration": f"{duration:.2f}s"
        }
    }
    export_results(report_items, args.json, args.csv, args.html, report_meta=meta, theme=getattr(args, "theme", None))


def handle_sniff(args):
    run_packet_sniffer(
        interface=args.interface,
        count=args.count,
        timeout=args.timeout,
        bpf_filter=args.filter,
        pcap_file=args.pcap
    )


def handle_serve(args):
    start_server(host=args.host, port=args.port)


def handle_config(args):
    current = load_config()
    if args.set:
        key, val = args.set
        # Auto convert numbers
        if val.isdigit():
            val = int(val)
        elif val.lower() == "true":
            val = True
        elif val.lower() == "false":
            val = False
        current[key] = val
        save_config(current, is_global=args.global_conf)
    else:
        print("\nCurrent Configuration:")
        print("=" * 45)
        for k, v in current.items():
            print(f"  {k:<24} = {v}")
        print("=" * 45)


def handle_ping(args):
    target = args.target

    if args.local or not target:
        local_info = get_local_subnet()
        target = local_info["cidr"]
        print(f"[*] Auto-detected local subnet: {target} (Interface: {local_info['interface']}, Gateway: {local_info['gateway']})")

    is_cidr = "/" in target
    start_time = time.time()

    if is_cidr:
        print(f"[*] Performing multi-threaded ping sweep across {target} (Threads: {args.threads})...")
        results = ping_sweep(target, max_workers=args.threads, timeout=args.timeout)
        duration = time.time() - start_time

        print("\n" + "=" * 105)
        print(f"{'IP ADDRESS':<16} | {'STATUS':<7} | {'LATENCY':<9} | {'TTL':<5} | {'ESTIMATED OS':<20} | {'DEVICE ROLE':<20} | {'NAME / TAG'}")
        print("-" * 105)

        for r in results:
            label = r["Label"] or r["Hostname"] or "-"
            dtype = r.get("DeviceType", "Device")
            print(f"{r['IP']:<16} | {r['Status']:<7} | {r['Latency']:<9} | {str(r['TTL']):<5} | {r['OS_Guess'][:20]:<20} | {dtype[:20]:<20} | {label}")

        print("=" * 105)
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
        export_results(results, args.json, args.csv, args.html, svg_path=args.svg, report_meta=meta, theme=getattr(args, "theme", None))

    else:
        print(f"[*] Pinging {target} ({args.count} packets, {args.timeout}s timeout)...")

        # Display WAN GeoIP intelligence for public IPs
        if is_public_ip(target):
            geo = get_ip_geolocation(target)
            if geo.get("status") == "success":
                print(format_geo_banner(geo))

        res = execute_ping(target, count=args.count, timeout=args.timeout)
        duration = time.time() - start_time

        tag_info = DeviceTagManager.get_tag(target)
        label = tag_info["label"] if tag_info else ""
        device_type, confidence, details = classify_device(
            ip=target,
            hostname=resolve_hostname(target),
            ttl=res["ttl"]
        )

        print("\n" + "=" * 65)
        print(f"Ping Results for: {target} {f'({label})' if label else ''}")
        print("-" * 65)
        if res["alive"]:
            print(f"Status:       [REACHABLE / ONLINE]")
            print(f"Device Role:  {device_type} ({details})")
            print(f"Latency:      min = {res['rtt_min']}ms | avg = {res['rtt_avg']}ms | max = {res['rtt_max']}ms")
            print(f"Jitter:       {res['jitter']}ms")
            print(f"Packet Loss:  {res['loss_percent']}%")
            print(f"TTL:          {res['ttl']} (Estimated Hops: {res['hops']})")
            print(f"OS Guess:     {res['os_guess']}")
        else:
            print(f"Status:       [UNREACHABLE / 100% PACKET LOSS]")
        print("=" * 65)

        report_data = [{
            "Target": target,
            "Status": "ONLINE" if res["alive"] else "OFFLINE",
            "DeviceType": device_type,
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
                "Device Role": device_type,
                "Packet Loss": f"{res['loss_percent']}%",
                "Latency": f"{res['rtt_avg']}ms" if res["rtt_avg"] else "-",
                "OS Guess": res["os_guess"]
            }
        }
        export_results(report_data, args.json, args.csv, args.html, report_meta=meta, theme=getattr(args, "theme", None))


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


def handle_wifi(args):
    print(f"[*] Starting Wireless / Wi-Fi Reconnaissance & Security Audit (Timeout: {args.timeout}s)...")
    res = scan_wifi(interface=args.interface, timeout=args.timeout)
    print_wifi_results(res)
    if args.json:
        from network_scanner.reports.json_report import export_json
        export_json(res.get("networks", []), args.json)
    if args.csv:
        from network_scanner.reports.csv_report import export_csv
        export_csv(res.get("networks", []), args.csv)


def handle_geo(args):
    print(f"[*] Querying Geolocation and WAN Intelligence for: {args.IP}...")
    geo_info = get_ip_geolocation(args.IP, timeout=args.timeout)
    banner = format_geo_banner(geo_info)
    print("\n" + banner + "\n")
    if args.json:
        from network_scanner.reports.json_report import export_json
        export_json([geo_info], args.json)


def main():
    parser = argparse.ArgumentParser(
        description=f"Network Scanner Suite (v{__version__}) - Layer 2/3/4 Reconnaissance, OS Detection, and Security Auditing Toolkit."
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Command to perform.", required=True)

    # -----------------------------
    # ARP Subcommand
    # -----------------------------
    arp_parser = subparsers.add_parser("ARP", help="Perform ARP discovery on a local network.")
    arp_parser.add_argument("IP", nargs="?", help="An IP address or CIDR range. If omitted, pass --local.")
    arp_parser.add_argument("--local", action="store_true", help="Auto-detect local interface subnet and scan.")
    arp_parser.add_argument("--watch", type=int, nargs="?", const=15, metavar="SECONDS",
                            help="Run in continuous watch mode (default: 15s interval). Alerts on new devices.")
    arp_parser.add_argument("--webhook", help="Webhook URL (Discord/Slack) for instant alerts on device connect/disconnect.")
    arp_parser.add_argument("--no-resolve", action="store_true", help="Skip reverse DNS hostname resolution.")
    arp_parser.add_argument("--no-history", action="store_true", help="Do not compare or record scan history.")
    arp_parser.add_argument("--json", help="Export results to a JSON file.")
    arp_parser.add_argument("--csv", help="Export results to a CSV file.")
    arp_parser.add_argument("--html", help="Export a styled interactive HTML security audit report.")
    arp_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                            help="Initial HTML report visual theme (dark, light, cyberpunk).")
    arp_parser.add_argument("--svg", help="Export a visual SVG network topology diagram.")

    # -----------------------------
    # TCP Subcommand
    # -----------------------------
    tcp_parser = subparsers.add_parser("TCP", help="Perform a TCP port scan.")
    tcp_parser.add_argument("IP", help="An IP address or hostname to target.")
    tcp_parser.add_argument(
        "ports", nargs="*", type=int, default=[],
        help="Specific ports to scan (e.g. 80 443 22). If empty and no --range/--top-ports, defaults to top 20 ports."
    )
    tcp_parser.add_argument("--range", action="store_true", help="Scan a port range (provide exactly 2 ports).")
    tcp_parser.add_argument("--top-ports", type=int, metavar="N", help="Scan top N common ports (up to 22).")
    tcp_parser.add_argument("--syn", action="store_true", help="Perform raw TCP SYN half-open scan (requires root/sudo).")
    tcp_parser.add_argument("--timeout", type=float, help="Socket connection timeout in seconds.")
    tcp_parser.add_argument("--threads", type=int, help="Number of concurrent threads.")
    tcp_parser.add_argument("--no-banner", action="store_true", help="Skip service banner grabbing.")
    tcp_parser.add_argument("--json", help="Export results to a JSON file.")
    tcp_parser.add_argument("--csv", help="Export results to a CSV file.")
    tcp_parser.add_argument("--html", help="Export a styled interactive HTML security audit report.")
    tcp_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                            help="Initial HTML report visual theme (dark, light, cyberpunk).")

    # -----------------------------
    # UDP Subcommand
    # -----------------------------
    udp_parser = subparsers.add_parser("UDP", help="Perform a UDP service and port scan.")
    udp_parser.add_argument("IP", help="An IP address or hostname to target.")
    udp_parser.add_argument("ports", nargs="*", type=int, default=[], help="Specific UDP ports to scan.")
    udp_parser.add_argument("--range", action="store_true", help="Scan a port range.")
    udp_parser.add_argument("--top-ports", type=int, metavar="N", help="Scan top N common UDP ports.")
    udp_parser.add_argument("--timeout", type=float, help="UDP socket timeout in seconds.")
    udp_parser.add_argument("--threads", type=int, default=30, help="Number of concurrent threads.")
    udp_parser.add_argument("--json", help="Export results to a JSON file.")
    udp_parser.add_argument("--csv", help="Export results to a CSV file.")
    udp_parser.add_argument("--html", help="Export a styled interactive HTML security audit report.")
    udp_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                            help="Initial HTML report visual theme (dark, light, cyberpunk).")

    # -----------------------------
    # SNMP Subcommand
    # -----------------------------
    snmp_parser = subparsers.add_parser("SNMP", help="Perform MIB-II SNMP system and interface enumeration.")
    snmp_parser.add_argument("IP", help="An IP address or hostname running an SNMP agent.")
    snmp_parser.add_argument("--community", help="SNMP community string.")
    snmp_parser.add_argument("--port", type=int, default=161, help="SNMP UDP port (default: 161).")
    snmp_parser.add_argument("--timeout", type=float, default=1.5, help="Query timeout in seconds.")
    snmp_parser.add_argument("--json", help="Export results to a JSON file.")
    snmp_parser.add_argument("--csv", help="Export results to a CSV file.")
    snmp_parser.add_argument("--html", help="Export a styled interactive HTML report.")
    snmp_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                             help="Initial HTML report visual theme (dark, light, cyberpunk).")

    # -----------------------------
    # SMB Subcommand
    # -----------------------------
    smb_parser = subparsers.add_parser("SMB", help="Perform SMB protocol negotiation, signing, and host audit.")
    smb_parser.add_argument("IP", help="An IP address or hostname running SMB (port 445).")
    smb_parser.add_argument("--port", type=int, default=445, help="SMB TCP port (default: 445).")
    smb_parser.add_argument("--timeout", type=float, default=2.0, help="Query timeout in seconds.")
    smb_parser.add_argument("--json", help="Export results to a JSON file.")
    smb_parser.add_argument("--csv", help="Export results to a CSV file.")
    smb_parser.add_argument("--html", help="Export a styled interactive HTML report.")
    smb_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                            help="Initial HTML report visual theme (dark, light, cyberpunk).")

    # -----------------------------
    # DNS Subcommand (NEW!)
    # -----------------------------
    dns_parser = subparsers.add_parser("DNS", help="Query DNS records and test AXFR zone transfers.")
    dns_parser.add_argument("target", help="Domain name or host to query (e.g., example.com).")
    dns_parser.add_argument("--server", help="Specific DNS server IP to query.")
    dns_parser.add_argument("--timeout", type=float, default=2.0, help="Query timeout in seconds.")
    dns_parser.add_argument("--json", help="Export results to a JSON file.")
    dns_parser.add_argument("--csv", help="Export results to a CSV file.")
    dns_parser.add_argument("--html", help="Export a styled interactive HTML report.")
    dns_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                            help="Initial HTML report visual theme (dark, light, cyberpunk).")

    # -----------------------------
    # SNIFF Subcommand (NEW!)
    # -----------------------------
    sniff_parser = subparsers.add_parser("SNIFF", help="Capture and inspect live network traffic (ARP, DNS, DHCP, ICMP).")
    sniff_parser.add_argument("--interface", "-i", help="Network interface to listen on.")
    sniff_parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 = continuous).")
    sniff_parser.add_argument("--timeout", "-t", type=float, help="Stop capture after N seconds.")
    sniff_parser.add_argument("--filter", "-f", default="arp or icmp or port 53 or port 67 or port 68",
                              help="BPF filter expression.")
    sniff_parser.add_argument("--pcap", "-w", help="Save captured packets to a PCAP file for Wireshark.")

    # -----------------------------
    # WIFI Subcommand (NEW!)
    # -----------------------------
    wifi_parser = subparsers.add_parser("WIFI", help="Discover nearby Wi-Fi networks and audit wireless security.")
    wifi_parser.add_argument("--interface", "-i", help="Wireless network interface to use.")
    wifi_parser.add_argument("--timeout", "-t", type=float, default=8.0, help="Scan timeout in seconds.")
    wifi_parser.add_argument("--json", help="Export results to a JSON file.")
    wifi_parser.add_argument("--csv", help="Export results to a CSV file.")

    # -----------------------------
    # GEO Subcommand (NEW!)
    # -----------------------------
    geo_parser = subparsers.add_parser("GEO", help="Query Geolocation, ASN, ISP, and WAN metadata for public IPs.")
    geo_parser.add_argument("IP", help="Public IP address or hostname to locate.")
    geo_parser.add_argument("--timeout", "-t", type=float, default=3.0, help="Query timeout in seconds.")
    geo_parser.add_argument("--json", help="Export results to a JSON file.")

    # -----------------------------
    # SERVE Subcommand (NEW!)
    # -----------------------------
    serve_parser = subparsers.add_parser("SERVE", help="Start the embedded Web Dashboard and REST API daemon.")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Listening address (default: 127.0.0.1).")
    serve_parser.add_argument("--port", "-p", type=int, default=8080, help="Listening port (default: 8080).")

    # -----------------------------
    # CONFIG Subcommand (NEW!)
    # -----------------------------
    config_parser = subparsers.add_parser("CONFIG", help="View or modify scanner default preferences.")
    config_parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Update a config key (e.g., --set threads 100).")
    config_parser.add_argument("--global", dest="global_conf", action="store_true", help="Modify global user configuration.")

    # -----------------------------
    # PING Subcommand
    # -----------------------------
    ping_parser = subparsers.add_parser("PING", help="Check host reachability, latency, packet loss, and OS fingerprint.")
    ping_parser.add_argument("target", nargs="?", help="Target IP, hostname, or CIDR range.")
    ping_parser.add_argument("--local", action="store_true", help="Auto-detect local subnet and run ping sweep.")
    ping_parser.add_argument("--count", "-c", type=int, default=4, help="Packets to send (single host, default: 4).")
    ping_parser.add_argument("--timeout", "-W", type=float, default=1.0, help="Timeout in seconds.")
    ping_parser.add_argument("--threads", type=int, default=50, help="Threads for ping sweep.")
    ping_parser.add_argument("--json", help="Export results to a JSON file.")
    ping_parser.add_argument("--csv", help="Export results to a CSV file.")
    ping_parser.add_argument("--html", help="Export a styled interactive HTML report.")
    ping_parser.add_argument("--theme", choices=["dark", "light", "cyberpunk"], default=None,
                             help="Initial HTML report visual theme (dark, light, cyberpunk).")
    ping_parser.add_argument("--svg", help="Export a visual SVG network topology diagram.")

    # -----------------------------
    # TAG Subcommand
    # -----------------------------
    tag_parser = subparsers.add_parser("TAG", help="Manage labels and notes for network devices.")
    tag_parser.add_argument("target", nargs="?", help="IP address or MAC address to tag.")
    tag_parser.add_argument("label", nargs="?", help="Friendly name / label.")
    tag_parser.add_argument("--notes", help="Optional detailed notes.")
    tag_parser.add_argument("--list", action="store_true", help="List all saved device tags.")
    tag_parser.add_argument("--delete", help="Delete the tag for the given IP or MAC.")

    args = parser.parse_args()

    if args.command == "ARP":
        handle_arp(args)
    elif args.command == "TCP":
        handle_tcp(args)
    elif args.command == "UDP":
        handle_udp(args)
    elif args.command == "SNMP":
        handle_snmp(args)
    elif args.command == "SMB":
        handle_smb(args)
    elif args.command == "DNS":
        handle_dns(args)
    elif args.command == "SNIFF":
        handle_sniff(args)
    elif args.command == "WIFI":
        handle_wifi(args)
    elif args.command == "GEO":
        handle_geo(args)
    elif args.command == "SERVE":
        handle_serve(args)
    elif args.command == "CONFIG":
        handle_config(args)
    elif args.command == "PING":
        handle_ping(args)
    elif args.command == "TAG":
        handle_tag(args)


if __name__ == "__main__":
    main()

