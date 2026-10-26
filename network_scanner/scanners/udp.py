"""
High-Performance UDP Port Scanner with Protocol-Specific Payload Probing.
Detects active UDP services including DNS, DHCP, NTP, SNMP, SSDP, TFTP, NetBIOS, and mDNS.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from network_scanner.constants import SECURITY_WARNINGS
from network_scanner.utils.network import get_service_name

# Crafted probe payloads for common UDP protocols to solicit positive replies
UDP_PROBES = {
    # DNS: Standard query for root zone
    53: b"\x10\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    # TFTP: Read Request (RRQ) for test.txt
    69: b"\x00\x01test.txt\x00octet\x00",
    # NTP: Client request (version 3, mode 3)
    123: b"\x1b" + 47 * b"\x00",
    # NetBIOS Name Service: Node Status Request for CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    137: (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    ),
    # SNMP: v2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) with 'public' community
    161: (
        b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02"
        b"\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06"
        b"\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),
    # SSDP / UPnP: M-SEARCH discovery query
    1900: (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 2\r\n"
        b"ST: ssdp:all\r\n\r\n"
    ),
    # mDNS: Standard multicast DNS query
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
}


def probe_udp_port(ip, port, timeout=1.5):
    """
    Sends a tailored UDP probe and awaits a response.
    Returns result dict if the port responds (is confirmed OPEN), else None.
    """
    payload = UDP_PROBES.get(port, b"\x00" * 8)
    start_time = time.time()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            data, _ = s.recvfrom(2048)
            latency_ms = (time.time() - start_time) * 1000.0

            service = get_service_name(port, proto="udp")
            banner_summary = ""

            if port == 53:
                banner_summary = "DNS Server (Valid Response)"
            elif port == 123:
                banner_summary = "NTP Clock Server (Active)"
            elif port == 161:
                banner_summary = "SNMP Agent (Responded to public community)"
            elif port == 1900:
                text = data.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        banner_summary = line.strip()
                        break
                if not banner_summary:
                    banner_summary = "UPnP / SSDP Service"
            elif port == 137:
                banner_summary = "NetBIOS Name Service"
            else:
                banner_summary = f"Received {len(data)} bytes UDP reply"

            return {
                "port": port,
                "protocol": "UDP",
                "state": "OPEN",
                "service": service,
                "latency_ms": round(latency_ms, 1),
                "banner": banner_summary,
                "warning": SECURITY_WARNINGS.get(port, "")
            }

    except (socket.timeout, OSError):
        return None


def udp_scan(ip, ports, timeout=1.5, max_workers=30):
    """
    Scans a list of UDP ports against target IP concurrently.
    Returns:
        list of open port records.
    """
    discovered_ports = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as executor:
        futures = {executor.submit(probe_udp_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            res = future.result()
            if res:
                discovered_ports.append(res)

    discovered_ports.sort(key=lambda x: x["port"])
    return discovered_ports
