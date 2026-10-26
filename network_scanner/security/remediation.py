"""
Automated Security Remediation and Device Isolation Engine.
Generates and executes Linux firewall rules (iptables/nftables) to isolate rogue or vulnerable hosts.
"""

import os
import shutil
import subprocess


def generate_isolation_rules(ip):
    """
    Generates host firewall isolation commands for Linux (iptables & nftables).
    """
    return [
        f"iptables -I INPUT 1 -s {ip} -j DROP",
        f"iptables -I FORWARD 1 -s {ip} -j DROP",
        f"iptables -I OUTPUT 1 -d {ip} -j DROP"
    ]


def isolate_device(ip):
    """
    Executes immediate device isolation via iptables if running with root privileges.

    Returns:
        tuple: (success: bool, message: str)
    """
    if os.geteuid() != 0:
        return False, f"Root privileges required. Run manually: sudo iptables -I INPUT 1 -s {ip} -j DROP"

    if not shutil.which("iptables"):
        return False, "iptables utility not found on this system."

    cmds = generate_isolation_rules(ip)
    for cmd in cmds:
        try:
            subprocess.run(cmd.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            return False, f"Failed executing '{cmd}': {e}"

    return True, f"Successfully isolated host {ip} using iptables."


def export_remediation_script(ip_list, output_file="isolate_rogue_devices.sh"):
    """
    Exports a standalone, executable Bash script to isolate specified devices.
    """
    lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated Device Isolation Script by Network Scanner Suite v2.0",
        "set -euo pipefail",
        "",
        "if [ \"$EUID\" -ne 0 ]; then",
        "  echo \"[!] Please run as root: sudo $0\"",
        "  exit 1",
        "fi",
        "",
        "echo \"[*] Applying firewall isolation rules...\"",
        ""
    ]

    for ip in ip_list:
        lines.append(f"# Block {ip}")
        for rule in generate_isolation_rules(ip):
            lines.append(rule)
        lines.append(f"echo \"[+] Isolated {ip}\"")
        lines.append("")

    lines.append("echo \"[✓] All specified devices isolated.\"")
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(output_file, 0o755)
    return output_file
