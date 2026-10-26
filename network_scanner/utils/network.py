"""
Hardware, IP, and Network Resolution Utilities.
"""

import ipaddress
import socket
import struct
import os

# Silence Scapy startup messages
os.environ["SCAPY_USE_PCAPDNET"] = "False"
from scapy.all import conf  # noqa: E402
conf.verb = 0


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
    if not mac or mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return "Broadcast / Unknown"

    try:
        first_byte = int(mac.split(":")[0], 16)
        # Check locally administered / randomized bit
        if first_byte & 2:
            return "Randomized / Private MAC"
    except Exception:
        pass

    try:
        vendor_resolved = conf.manufdb._resolve_MAC(mac)
        if vendor_resolved and vendor_resolved != mac:
            parts = vendor_resolved.split(":")
            if len(parts) > 1 and parts[0]:
                return parts[0].strip()
            return vendor_resolved.strip()
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


def get_service_name(port, proto="tcp"):
    """Retrieves standard service name for a given port."""
    try:
        return socket.getservbyport(port, proto).upper()
    except OSError:
        common = {
            21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
            67: "DHCP-SRV", 68: "DHCP-CLI", 69: "TFTP", 80: "HTTP", 110: "POP3",
            123: "NTP", 135: "RPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM",
            139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
            500: "ISAKMP", 514: "SYSLOG", 520: "RIP", 631: "IPP", 993: "IMAPS",
            995: "POP3S", 1723: "PPTP", 1900: "SSDP", 3306: "MYSQL", 3389: "RDP",
            4500: "NAT-T", 5353: "MDNS", 5432: "POSTGRESQL", 5900: "VNC",
            6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB"
        }
        return common.get(port, "UNKNOWN")
