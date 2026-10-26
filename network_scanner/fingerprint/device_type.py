"""
Intelligent Device Type Classification & Profiling.
Infers hardware role (Router, NAS, Printer, Mobile, IoT, Desktop, Server)
by synthesizing MAC vendor, hostname heuristics, open ports, and TTL.
"""

import re


def classify_device(ip, mac="", vendor="", hostname="", open_ports=None, ttl=None, is_gateway=False):
    """
    Classifies a device into a human-friendly role / hardware profile.

    Returns:
        tuple: (category: str, confidence: str, details: str)
    """
    ports = set(open_ports or [])
    vendor_lower = (vendor or "").lower()
    host_lower = (hostname or "").lower()
    ip_parts = ip.split(".")
    last_octet = ip_parts[-1] if len(ip_parts) == 4 else ""

    # 1. Router / Gateway / Access Point
    if is_gateway or host_lower.startswith("_gateway"):
        return "Router / Gateway", "High", f"{vendor or 'Network Gateway'} (Default Gateway)"

    router_keywords = ["router", "gateway", "modem", "ap-", "openwrt", "ddwrt", "unifi", "amplifi", "mikrotik", "fritz"]
    if any(k in host_lower for k in router_keywords):
        return "Router / Gateway", "High", f"{vendor or 'Network'} Router"

    router_vendors = ["cisco", "netgear", "tp-link", "huawei", "d-link", "ubiquiti", "mikrotik", "arris", "zyxel", "technicolor", "sagemcom"]
    if any(v in vendor_lower for v in router_vendors):
        if last_octet in ("1", "254") or 53 in ports or 67 in ports or 1900 in ports:
            return "Router / Gateway", "High", f"{vendor} Gateway/AP"

    # 2. Printer / Multi-Function Printer (MFP)
    printer_ports = {515, 631, 9100}
    printer_vendors = ["brother", "canon", "epson", "xerox", "lexmark", "kyocera", "ricoh"]
    if ports & printer_ports:
        return "Printer / Scanner", "High", f"{vendor or 'Network'} Printer (JetDirect/IPP active)"

    if any(pv in vendor_lower for pv in printer_vendors) or any(k in host_lower for k in ["print", "mfp", "laserjet", "deskjet"]):
        return "Printer / Scanner", "High", f"{vendor or 'Network'} Printer"

    # 3. NAS / Storage Device
    nas_keywords = ["nas", "synology", "qnap", "truenas", "freenas", "diskstation", "readynas"]
    nas_vendors = ["synology", "qnap", "buffalo", "asustor", "drobo"]
    if any(k in host_lower for k in nas_keywords) or any(v in vendor_lower for v in nas_vendors):
        return "NAS / Storage Server", "High", f"{vendor or 'Network'} Storage Appliance"

    if 2049 in ports or {5000, 5001} & ports or (445 in ports and 8080 in ports and ttl == 64):
        return "NAS / Storage Server", "Medium", f"{vendor or 'Network'} File Storage"

    # 4. Mobile Devices (Smartphones & Tablets)
    mobile_patterns = [
        r"iphone", r"ipad", r"android", r"galaxy", r"s2[0-5]", r"pixel",
        r"xiaomi", r"redmi", r"oneplus", r"oppo", r"vivo", r"honor"
    ]
    if any(re.search(pat, host_lower) for pat in mobile_patterns):
        return "Mobile (Phone/Tablet)", "High", f"{vendor or 'Mobile'} Device"

    # Randomized MAC with Linux TTL and no server ports
    if vendor == "Randomized / Private MAC" and (ttl is None or ttl <= 64):
        if not (ports & {22, 80, 443, 3306, 5432, 27017}):
            return "Mobile (Phone/Tablet)", "Medium", "Likely Smartphone/Tablet (Private MAC)"

    # 5. IoT & Smart Home Devices
    iot_vendors = [
        "espressif", "tuya", "hikvision", "dahua", "sonos", "roku", "philips lighting",
        "amazon technologies", "wyze", "nest", "belkin", "ring", "ecobee", "tplink smart"
    ]
    iot_keywords = ["cam", "camera", "dvr", "nvr", "sonos", "roku", "chromecast", "nest", "hue", "tasmota", "wemo", "smart", "iot"]
    if any(v in vendor_lower for v in iot_vendors) or any(k in host_lower for k in iot_keywords):
        return "IoT / Smart Device", "High", f"{vendor or 'Smart'} Connected Device"

    if 554 in ports:  # RTSP Camera
        return "IoT (IP Camera)", "High", f"{vendor or 'Surveillance'} Camera (RTSP exposed)"

    # 6. Desktop / Workstation PC
    desktop_vendors = ["dell", "hp", "hewlett packard", "lenovo", "acer", "asustek", "msi", "apple"]
    if ttl and 65 <= ttl <= 128:
        # Windows
        if any(v in vendor_lower for v in desktop_vendors) or any(k in host_lower for k in ["desktop", "laptop", "pc", "win"]):
            return "Desktop / Workstation", "High", f"Windows PC ({vendor or 'OEM'})"
        return "Desktop / Workstation", "Medium", "Windows Host"

    if "apple" in vendor_lower:
        if any(k in host_lower for k in ["macbook", "imac", "mac-mini", "macpro"]):
            return "Desktop / Workstation", "High", "Apple Mac"
        if ttl == 64:
            return "Workstation / Device", "Medium", "Apple macOS / iOS Device"

    # 7. Server / Infrastructure
    server_ports = {22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017}
    if len(ports & server_ports) >= 2 or any(k in host_lower for k in ["server", "srv", "node", "prod", "k8s", "docker"]):
        return "Server / Infrastructure", "High", f"{vendor or 'Linux/Unix'} Application Server"

    # Default fallback
    if vendor and vendor != "Unknown Vendor":
        return "Network Device", "Low", f"{vendor} Host"

    return "Network Host", "Low", "Generic Connected Host"
