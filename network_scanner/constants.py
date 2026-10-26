"""
Constants, default port lists, security risk definitions, and lookup mappings.
"""

from pathlib import Path

HISTORY_FILE = Path(".scanner_history.json")
TAGS_FILE = Path(".scanner_tags.json")

COMMON_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
]

COMMON_UDP_PORTS = [
    53,    # DNS
    67,    # DHCP Server
    68,    # DHCP Client
    69,    # TFTP
    123,   # NTP
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
    161,   # SNMP
    500,   # ISAKMP / IPsec
    514,   # Syslog
    520,   # RIP
    1900,  # SSDP / UPnP
    4500,  # IPsec NAT-Traversal
    5353   # mDNS
]

SECURITY_WARNINGS = {
    21: "FTP transmits credentials and data in cleartext.",
    23: "Telnet is unencrypted and insecure. Use SSH instead.",
    69: "TFTP has no authentication or encryption mechanisms.",
    80: "HTTP transmits data in cleartext. Prefer HTTPS (443).",
    135: "RPC endpoint mapper exposed; common target for reconnaissance.",
    137: "NetBIOS Name Service exposed; potential for NetBIOS spoofing and info leak.",
    138: "NetBIOS Datagram Service exposed to local network.",
    139: "NetBIOS Session Service exposed to network.",
    161: "SNMP service exposed. Ensure v3 encryption or non-default community strings.",
    445: "SMB exposed; ensure SMBv1 is disabled and message signing is enforced.",
    514: "Syslog exposed; unencrypted log messages may be intercepted or spoofed.",
    1900: "SSDP / UPnP exposed; potential for amplification DDoS or unauthorized device control.",
    3306: "MySQL database port exposed. Avoid exposing database ports directly.",
    3389: "RDP exposed. Ensure NLA is enabled and strong passwords or VPN are used.",
    5432: "PostgreSQL database port exposed. Ensure access is strictly restricted.",
    5900: "VNC exposed. Ensure strong encryption and authentication.",
    6379: "Redis exposed without authentication by default; high risk of unauthorized execution.",
    27017: "MongoDB exposed; ensure authentication is enabled and bound to localhost.",
}

# Base risk scores per service (used for calculating 0-100 host and network risk score)
SERVICE_RISK_SCORES = {
    23: 35,     # Telnet (Critical cleartext)
    6379: 30,   # Redis (Unauth RCE vector)
    21: 25,     # FTP (Cleartext auth)
    445: 25,    # SMB (EternalBlue / ransomware lateral movement)
    27017: 25,  # MongoDB
    3306: 20,   # MySQL
    5432: 20,   # PostgreSQL
    3389: 20,   # RDP
    5900: 20,   # VNC
    161: 20,    # SNMP
    69: 20,     # TFTP
    135: 15,    # RPC
    137: 15,    # NetBIOS
    139: 15,    # NetBIOS
    80: 10,     # HTTP
    1900: 10,   # SSDP
    514: 10,    # Syslog
}
