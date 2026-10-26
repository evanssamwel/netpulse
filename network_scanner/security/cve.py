"""
Curated Offline CVE & Vulnerability Lookup Engine.
Matches detected software banners and versions against known high-impact vulnerabilities.
Zero internet or external API dependencies required.
"""

import re

# Curated database of prominent, high-impact network vulnerabilities
CVE_DATABASE = [
    # ------------------ Apache HTTP Server ------------------
    {
        "service": "HTTP",
        "pattern": r"apache/(?:2\.4\.49|2\.4\.50)\b",
        "cve": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "Apache 2.4.49, 2.4.50",
        "summary": "Path traversal and file disclosure flaw allowing remote attackers to execute arbitrary CGI scripts or access restricted files.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or newer immediately."
    },
    {
        "service": "HTTP",
        "pattern": r"apache/(?:2\.[0-3]\.|2\.4\.(?:[0-9]|1[0-9]|2[0-9]))\b",
        "cve": "CVE-2017-15715",
        "title": "Apache HTTP Server Arbitrary File Upload via FilesMatch Bypass",
        "severity": "HIGH",
        "cvss": 8.1,
        "affected": "Apache 2.4.0 to 2.4.29",
        "summary": "Expression matching in <FilesMatch> could be bypassed using trailing newline characters, leading to malicious file upload/execution.",
        "remediation": "Update Apache to version 2.4.30 or higher."
    },

    # ------------------ OpenSSH ------------------
    {
        "service": "SSH",
        "pattern": r"openssh(?: |_)8\.[5-9]|openssh(?: |_)9\.[0-7]",
        "cve": "CVE-2024-6387",
        "title": "OpenSSH 'regreSSHion' Unauthenticated Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "OpenSSH 8.5p1 to 9.7p1 on glibc Linux",
        "summary": "Signal handler race condition in sshd allowing unauthenticated root remote code execution.",
        "remediation": "Upgrade OpenSSH to version 9.8p1 or newer, or set LoginGraceTime 0 in sshd_config as interim workaround."
    },
    {
        "service": "SSH",
        "pattern": r"openssh(?: |_)(?:[0-6]\.|7\.[0-3])",
        "cve": "CVE-2016-10009",
        "title": "OpenSSH ssh-agent Arbitrary PKCS#11 Library Loading RCE",
        "severity": "HIGH",
        "cvss": 7.8,
        "affected": "OpenSSH before 7.4",
        "summary": "Untrusted PKCS#11 libraries can be loaded by forwarded ssh-agent, allowing code execution.",
        "remediation": "Upgrade OpenSSH to version 7.4 or newer."
    },

    # ------------------ Nginx ------------------
    {
        "service": "HTTP",
        "pattern": r"nginx/(?:1\.20\.0|1\.19\.[0-9]+)\b",
        "cve": "CVE-2021-23017",
        "title": "Nginx DNS Resolver 1-Byte Memory Overwrite RCE",
        "severity": "HIGH",
        "cvss": 8.5,
        "affected": "Nginx 0.6.18 - 1.20.0",
        "summary": "1-byte memory overwrite flaw in DNS resolver code allows remote attackers to cause worker crash or arbitrary code execution.",
        "remediation": "Upgrade Nginx to version 1.20.1 or 1.21.0 or newer."
    },

    # ------------------ vsftpd ------------------
    {
        "service": "FTP",
        "pattern": r"vsftpd 2\.3\.4\b",
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Smiley Face Backdoor RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "vsftpd 2.3.4",
        "summary": "Trojaned vsftpd release opens a root shell on TCP port 6200 when a username containing ':)' is provided.",
        "remediation": "Remove vsftpd 2.3.4 immediately and install a verified release (vsftpd 3.0.x)."
    },

    # ------------------ ProFTPD ------------------
    {
        "service": "FTP",
        "pattern": r"proftpd 1\.3\.5\b",
        "cve": "CVE-2015-3306",
        "title": "ProFTPD mod_copy Unauthenticated Arbitrary File Copy & RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "ProFTPD 1.3.5",
        "summary": "mod_copy extension allows unauthenticated attackers to copy arbitrary files to web-accessible directories using SITE CPFR / SITE CPTO commands.",
        "remediation": "Upgrade ProFTPD to 1.3.5a or newer, or disable mod_copy."
    },

    # ------------------ Redis ------------------
    {
        "service": "Redis",
        "pattern": r"redis (?:4\.|5\.|6\.0\.|6\.2\.[0-6])",
        "cve": "CVE-2022-0543",
        "title": "Redis Debian/Ubuntu Package Lua Sandbox Escape RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected": "Redis on Debian/Ubuntu with dynamic Lua library",
        "summary": "Missing sandbox initialization in Lua scripting engine allows unauthenticated attackers to escape sandbox and execute arbitrary system commands.",
        "remediation": "Upgrade Redis package and enable authentication via 'requirepass'."
    },

    # ------------------ SMB / Windows ------------------
    {
        "service": "SMB",
        "pattern": r"smbv1",
        "cve": "CVE-2017-0144",
        "title": "MS17-010 'EternalBlue' SMBv1 Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "Microsoft Windows SMBv1 servers",
        "summary": "Critical vulnerability in SMBv1 handling of specific packets allowing unauthenticated remote code execution (used by WannaCry/NotPetya).",
        "remediation": "Disable SMBv1 completely across all network hosts and enforce SMBv2/v3."
    }
]


def lookup_cves(service, version_or_banner):
    """
    Scans a service name and version/banner string for known CVEs.

    Returns:
        list of CVE match dicts.
    """
    if not version_or_banner:
        return []

    combined_text = f"{service} {version_or_banner}".lower()
    matches = []

    for entry in CVE_DATABASE:
        if entry["service"].lower() in combined_text or service.upper() == entry["service"]:
            if re.search(entry["pattern"], combined_text, re.IGNORECASE):
                matches.append(entry)

    return matches


def audit_host_vulnerabilities(ports_list):
    """
    Audits a list of open ports with banners for CVE vulnerabilities.

    Returns:
        dict: {
            "cves": list of matched CVEs,
            "max_cvss": float,
            "has_critical": bool
        }
    """
    found_cves = []
    max_cvss = 0.0

    for p in ports_list:
        service = p.get("service", "")
        banner = p.get("version") or p.get("banner", "")
        matches = lookup_cves(service, banner)
        for m in matches:
            if m not in found_cves:
                found_cves.append(m)
                if m.get("cvss", 0) > max_cvss:
                    max_cvss = m["cvss"]

    return {
        "cves": found_cves,
        "max_cvss": max_cvss,
        "has_critical": any(c.get("severity") == "CRITICAL" for c in found_cves)
    }
