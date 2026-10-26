"""
ICMP Ping and Latency Sweeper.
Measures min/avg/max latency, jitter, packet loss, and fingerprints target OS via TTL.
"""

import ipaddress
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from network_scanner.fingerprint.device_type import classify_device
from network_scanner.fingerprint.ttl import fingerprint_os_from_ttl
from network_scanner.inventory.tags import DeviceTagManager
from network_scanner.utils.network import resolve_hostname


def execute_ping(target, count=2, timeout=1.0):
    """
    Sends ICMP echo requests using the system ping command.
    Captures reachability, packet loss, RTT stats, and TTL for OS fingerprinting.
    """
    cmd = ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), target]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 2)
        out = res.stdout
    except Exception:
        return {
            "alive": False,
            "loss_percent": 100.0,
            "rtt_avg": None,
            "rtt_min": None,
            "rtt_max": None,
            "jitter": None,
            "ttl": None,
            "os_guess": "Unknown",
            "hops": 0
        }

    # Extract packet loss
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out)
    loss = float(loss_match.group(1)) if loss_match else 100.0

    # Extract TTL
    ttl_match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
    ttl = int(ttl_match.group(1)) if ttl_match else None

    # Extract RTT min/avg/max/mdev
    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)",
        out
    )
    if rtt_match:
        rtt_min, rtt_avg, rtt_max, jitter = map(float, rtt_match.groups())
    else:
        rtt_min, rtt_avg, rtt_max, jitter = None, None, None, None

    os_guess, hops = fingerprint_os_from_ttl(ttl)

    return {
        "alive": res.returncode == 0 and loss < 100.0,
        "loss_percent": loss,
        "rtt_avg": rtt_avg,
        "rtt_min": rtt_min,
        "rtt_max": rtt_max,
        "jitter": jitter,
        "ttl": ttl,
        "os_guess": os_guess,
        "hops": hops
    }


def ping_sweep(network_cidr, max_workers=50, timeout=1.0):
    """
    Performs a multi-threaded ping sweep over a CIDR block.
    Returns list of discovered hosts and latency metrics.
    """
    net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()]

    active_hosts = []

    def probe(ip_str):
        p_res = execute_ping(ip_str, count=1, timeout=timeout)
        if p_res["alive"]:
            tag_info = DeviceTagManager.get_tag(ip_str)
            hostname = resolve_hostname(ip_str)
            device_type, confidence, details = classify_device(
                ip=ip_str,
                hostname=hostname,
                ttl=p_res["ttl"]
            )
            return {
                "IP": ip_str,
                "Status": "ALIVE",
                "Latency": f"{p_res['rtt_avg']}ms" if p_res["rtt_avg"] else "<1ms",
                "TTL": p_res["ttl"] or "-",
                "OS_Guess": p_res["os_guess"],
                "DeviceType": device_type,
                "Hops": p_res["hops"],
                "Hostname": hostname,
                "Label": tag_info["label"] if tag_info else "",
                "Notes": tag_info["notes"] if tag_info else ""
            }
        return None

    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts) or 1)) as executor:
        futures = {executor.submit(probe, ip): ip for ip in hosts}
        for future in as_completed(futures):
            res = future.result()
            if res:
                active_hosts.append(res)

    active_hosts.sort(key=lambda x: ipaddress.IPv4Address(x["IP"]))
    return active_hosts
