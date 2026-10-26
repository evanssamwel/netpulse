"""
Security Risk Scoring & Remediation Recommendation Engine.
Calculates host and network risk scores (0-100) with prioritized security alerts.
"""

from network_scanner.constants import SECURITY_WARNINGS, SERVICE_RISK_SCORES


def calculate_host_risk(open_ports, service_details=None):
    """
    Computes a normalized risk score (0-100) for a target based on open ports.

    Returns:
        dict: {
            "score": int (0-100),
            "level": str ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
            "color": str,
            "findings": list of finding strings,
            "recommendations": list of actionable remediation steps
        }
    """
    ports = [p["port"] if isinstance(p, dict) else p for p in (open_ports or [])]
    findings = []
    recommendations = []
    total_score = 0

    for port in ports:
        score_val = SERVICE_RISK_SCORES.get(port, 0)
        warning_msg = SECURITY_WARNINGS.get(port)

        if score_val > 0:
            total_score += score_val

        if warning_msg:
            findings.append(f"Port {port}: {warning_msg}")

        # Tailored security recommendations
        if port == 23:
            recommendations.append("Disable Telnet immediately and migrate remote administration to SSH (Port 22).")
        elif port == 21:
            recommendations.append("Migrate FTP to SFTP/SCP or FTPS with enforced TLS encryption.")
        elif port == 80:
            recommendations.append("Redirect unencrypted HTTP traffic to HTTPS (Port 443) with HSTS.")
        elif port == 445:
            recommendations.append("Enforce SMB signing, disable legacy SMBv1, and firewall port 445 from untrusted subnets.")
        elif port in (3306, 5432, 27017, 6379):
            recommendations.append(f"Port {port} database is exposed. Bind listener to localhost (127.0.0.1) or restrict via firewall.")
        elif port == 3389:
            recommendations.append("Enforce Network Level Authentication (NLA) on RDP and require VPN or multi-factor auth.")
        elif port == 5900:
            recommendations.append("VNC is exposed without strong transport encryption. Tunnel VNC through SSH or VPN.")
        elif port == 161:
            recommendations.append("Upgrade SNMP to v3 with SHA/AES encryption or restrict SNMP community strings.")

    # Bound score to [0, 100]
    normalized_score = min(100, total_score)

    if normalized_score == 0:
        level = "CLEAN"
        color = "#10b981"  # Emerald green
    elif normalized_score < 30:
        level = "LOW"
        color = "#38bdf8"  # Light blue
    elif normalized_score < 60:
        level = "MEDIUM"
        color = "#f59e0b"  # Amber warning
    elif normalized_score < 80:
        level = "HIGH"
        color = "#f97316"  # Orange
    else:
        level = "CRITICAL"
        color = "#ef4444"  # Red danger

    return {
        "score": normalized_score,
        "level": level,
        "color": color,
        "findings": findings,
        "recommendations": list(dict.fromkeys(recommendations))  # Unique list preserving order
    }


def calculate_network_risk(hosts):
    """
    Computes an aggregate security posture score across all scanned hosts.
    Returns:
        dict: {
            "network_score": int,
            "network_level": str,
            "critical_hosts_count": int,
            "high_risk_hosts_count": int,
            "total_open_risky_ports": int
        }
    """
    if not hosts:
        return {
            "network_score": 0,
            "network_level": "CLEAN",
            "critical_hosts": 0,
            "high_risk_hosts": 0,
            "risky_ports": 0
        }

    scores = []
    crit_count = 0
    high_count = 0
    total_risky = 0

    for h in hosts:
        ports = h.get("OpenPorts", [])
        risk = calculate_host_risk(ports)
        scores.append(risk["score"])
        if risk["level"] == "CRITICAL":
            crit_count += 1
        elif risk["level"] == "HIGH":
            high_count += 1
        total_risky += len(risk["findings"])

    avg_score = round(sum(scores) / len(scores)) if scores else 0
    # Blend average with peak risk
    peak_score = max(scores) if scores else 0
    network_score = min(100, round((avg_score * 0.6) + (peak_score * 0.4)))

    if network_score == 0:
        level = "CLEAN"
    elif network_score < 30:
        level = "LOW"
    elif network_score < 60:
        level = "MEDIUM"
    elif network_score < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "network_score": network_score,
        "network_level": level,
        "critical_hosts": crit_count,
        "high_risk_hosts": high_count,
        "risky_ports": total_risky
    }
