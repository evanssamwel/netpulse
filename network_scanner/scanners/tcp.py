"""
Multi-Threaded TCP Port Scanner (Safe Connect Scan & Raw SYN Half-Open Scan).
Integrates banner grabbing, service version detection, and security risk warnings.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from network_scanner.constants import SECURITY_WARNINGS
from network_scanner.fingerprint.services import grab_banner
from network_scanner.fingerprint.ttl import fingerprint_os_from_ttl
from network_scanner.utils.network import get_service_name

# Scapy imports for SYN scan
from scapy.all import IP, TCP, sr


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
                    service = get_service_name(port, proto="tcp")
                    version_info = ""
                    raw_banner = ""

                    if grab_banners:
                        banner_res = grab_banner(ip, port, timeout=min(timeout * 2, 1.2))
                        if banner_res.get("service") and banner_res["service"] != "UNKNOWN":
                            service = banner_res["service"]
                        version_info = banner_res.get("version", "")
                        raw_banner = banner_res.get("raw_banner", "")

                    display_banner = version_info or raw_banner or "-"
                    warning = SECURITY_WARNINGS.get(port, "")

                    return {
                        "port": port,
                        "protocol": "TCP",
                        "state": "OPEN",
                        "service": service,
                        "version": version_info,
                        "latency_ms": round(latency_ms, 1),
                        "banner": display_banner,
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
            service = get_service_name(port, proto="tcp")
            banner_res = grab_banner(ip, port, timeout=1.0)
            version_info = banner_res.get("version", "")
            display_banner = version_info or banner_res.get("raw_banner", "-")

            result.append({
                "port": port,
                "protocol": "TCP",
                "state": "OPEN",
                "service": service,
                "version": version_info,
                "latency_ms": 0.0,
                "ttl": ttl,
                "os_guess": os_guess,
                "banner": display_banner,
                "warning": SECURITY_WARNINGS.get(port, "")
            })

    result.sort(key=lambda x: x["port"])
    return result


def tcp_scan(ip, ports):
    """Legacy wrapper for backwards-compatibility."""
    results = tcp_connect_scan(ip, list(ports), grab_banners=False)
    return [r["port"] for r in results]
