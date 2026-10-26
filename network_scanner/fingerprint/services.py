"""
Service banner grabbing, protocol inspection, and precise version detection.
Supports HTTP, SSH, FTP, SMTP, MySQL, Redis, and generic TCP protocols.
"""

import re
import socket
import ssl


def parse_ssh_banner(banner):
    """Parses SSH software and version from identification string."""
    # Example: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    m = re.search(r"SSH-[\d\.]+-([^\r\n]+)", banner)
    if m:
        full_ver = m.group(1).strip()
        # Clean up OpenSSH formatting
        full_ver = full_ver.replace("OpenSSH_", "OpenSSH ").replace("_", " ")
        return "SSH", full_ver
    return "SSH", banner


def parse_http_banner(header_text):
    """Extracts Server header and HTML title from HTTP response."""
    server = ""
    title = ""

    server_match = re.search(r"^Server:\s*(.+)$", header_text, re.IGNORECASE | re.MULTILINE)
    if server_match:
        server = server_match.group(1).strip()

    title_match = re.search(r"<title>([^<]+)</title>", header_text, re.IGNORECASE)
    if title_match:
        title = title_match.group(1).strip()

    version_str = server
    if title and title != "301 Moved Permanently" and title != "404 Not Found":
        if version_str:
            version_str += f" ({title})"
        else:
            version_str = title

    return "HTTP", version_str


def parse_ftp_banner(banner):
    """Extracts FTP server software and version from 220 greeting."""
    # Examples: 220 (vsFTPd 3.0.3), 220 ProFTPD 1.3.5 Server, 220 Pure-FTPd [privsep]
    m = re.search(r"220[- ](?:\((.+?)\)|(.+))", banner)
    if m:
        text = (m.group(1) or m.group(2) or "").strip()
        # Remove trailing words like 'Server' or 'ready'
        text = re.sub(r"\s+(?:ready|server|service)[\.\!]?$", "", text, flags=re.IGNORECASE)
        return "FTP", text
    return "FTP", banner


def parse_smtp_banner(banner):
    """Extracts SMTP MTA software from 220 greeting."""
    m = re.search(r"220[- ].+?ESMTP\s*([^\r\n]+)", banner, re.IGNORECASE)
    if m:
        return "SMTP", m.group(1).strip()
    return "SMTP", banner


def parse_mysql_handshake(raw_bytes):
    """Parses MySQL / MariaDB server version from protocol handshake packet."""
    try:
        # MySQL initial handshake packet:
        # 3 bytes packet length, 1 byte sequence (0)
        # 1 byte protocol version (usually 10)
        # Null-terminated server version string
        if len(raw_bytes) > 5 and raw_bytes[4] == 10:
            null_pos = raw_bytes.find(b"\x00", 5)
            if null_pos != -1:
                ver_str = raw_bytes[5:null_pos].decode("ascii", errors="ignore")
                return "MySQL", f"MySQL/MariaDB {ver_str}"
    except Exception:
        pass
    return "MySQL", ""


def parse_redis_response(text):
    """Extracts Redis version from INFO or PING response."""
    m = re.search(r"redis_version:([0-9\.]+)", text)
    if m:
        return "Redis", f"Redis {m.group(1)}"
    if "PONG" in text or "ERR" in text or "NOAUTH" in text:
        return "Redis", "Redis Server"
    return "Redis", ""


def grab_banner(ip, port, timeout=1.2):
    """
    Connects to an open port and sends protocol-specific probes to retrieve banners.
    Returns:
        dict: {
            "service": str,
            "version": str,
            "raw_banner": str
        }
    """
    raw_banner = ""
    service = "UNKNOWN"
    version_info = ""

    try:
        if port == 443 or port == 8443:
            # TLS / HTTPS
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                with ctx.wrap_socket(s, server_hostname=ip) as ss:
                    ss.connect((ip, port))
                    req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetworkScanner/2.0\r\nConnection: close\r\n\r\n"
                    ss.sendall(req.encode("utf-8"))
                    data = ss.recv(1024).decode("utf-8", errors="ignore")
                    service, version_info = parse_http_banner(data)
                    raw_banner = data.splitlines()[0] if data else ""
                    return {"service": "HTTPS", "version": version_info, "raw_banner": raw_banner}

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            if port in (80, 8080):
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetworkScanner/2.0\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode("utf-8"))
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                service, version_info = parse_http_banner(resp)
                raw_banner = resp.splitlines()[0] if resp else ""

            elif port == 6379:
                s.sendall(b"INFO\r\n")
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                service, version_info = parse_redis_response(resp)
                raw_banner = resp.splitlines()[0] if resp else ""

            elif port == 3306:
                resp_bytes = s.recv(512)
                service, version_info = parse_mysql_handshake(resp_bytes)
                raw_banner = version_info

            elif port in (21, 22, 25, 110, 143):
                resp = s.recv(512).decode("utf-8", errors="ignore").strip()
                raw_banner = resp.splitlines()[0] if resp else ""
                if port == 22:
                    service, version_info = parse_ssh_banner(resp)
                elif port == 21:
                    service, version_info = parse_ftp_banner(resp)
                elif port == 25:
                    service, version_info = parse_smtp_banner(resp)
                else:
                    service = "POP3/IMAP"
                    version_info = raw_banner

            else:
                s.sendall(b"\r\n")
                resp = s.recv(512).decode("utf-8", errors="ignore").strip()
                if resp:
                    raw_banner = resp.splitlines()[0][:80]
                    version_info = raw_banner

    except Exception:
        pass

    return {
        "service": service,
        "version": version_info,
        "raw_banner": raw_banner
    }
