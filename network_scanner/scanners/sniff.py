"""
Network Packet Capture & Traffic Inspection (SNIFF).
Captures real-time ARP, DHCP, DNS, and ICMP packets for diagnostic and reconnaissance purposes.
Optionally exports captures to standard PCAP files for Wireshark inspection.
"""

import sys
from datetime import datetime

# Scapy sniffing tools
from scapy.all import ARP, DHCP, DNS, ICMP, IP, IPv6, sniff, wrpcap


def format_packet_summary(pkt):
    """Formats a concise terminal line describing the captured packet."""
    now_str = datetime.now().strftime("%H:%M:%S")

    if pkt.haslayer(ARP):
        op = "WHO-HAS" if pkt[ARP].op == 1 else "IS-AT"
        return f"[{now_str}] [ARP]  {op} {pkt[ARP].pdst} from {pkt[ARP].psrc} ({pkt[ARP].hwsrc})"

    if pkt.haslayer(DHCP):
        msg_type = "DISCOVER/REQUEST"
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}
                msg_type = types.get(opt[1], f"TYPE-{opt[1]}")
        src = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
        return f"[{now_str}] [DHCP] {msg_type} (Client: {src})"

    if pkt.haslayer(DNS):
        if pkt[DNS].qr == 0:  # Query
            qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore") if pkt[DNS].qd else "-"
            src = pkt[IP].src if pkt.haslayer(IP) else "Host"
            return f"[{now_str}] [DNS]  QUERY '{qname}' from {src}"
        else:  # Response
            return f"[{now_str}] [DNS]  RESPONSE ({pkt[DNS].ancount} answer(s))"

    if pkt.haslayer(ICMP):
        src = pkt[IP].src if pkt.haslayer(IP) else "-"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "-"
        t_name = "ECHO-REQ" if pkt[ICMP].type == 8 else ("ECHO-REPLY" if pkt[ICMP].type == 0 else f"TYPE-{pkt[ICMP].type}")
        return f"[{now_str}] [ICMP] {t_name} {src} -> {dst}"

    if pkt.haslayer(IP):
        return f"[{now_str}] [IP]   {pkt[IP].src} -> {pkt[IP].dst} ({pkt[IP].proto})"

    return f"[{now_str}] [PKT]  {pkt.summary()}"


def run_packet_sniffer(interface=None, count=0, timeout=None, bpf_filter="arp or icmp or port 53 or port 67 or port 68", pcap_file=None):
    """
    Executes a live packet sniffing session.

    Args:
        interface (str): Network interface to bind to (e.g., 'eth0', 'wlan0').
        count (int): Stop after N packets (0 = continuous).
        timeout (float): Stop after N seconds.
        bpf_filter (str): Berkeley Packet Filter expression.
        pcap_file (str): Output path to save captured packets.
    """
    print("\n" + "=" * 80)
    print(f"[*] Starting Packet Sniffer (Filter: '{bpf_filter}')")
    if interface:
        print(f"[*] Interface: {interface}")
    if pcap_file:
        print(f"[*] PCAP output target: {pcap_file}")
    print("[*] Press Ctrl+C to finish capture.")
    print("=" * 80)

    captured = []

    def packet_callback(pkt):
        captured.append(pkt)
        print(f"  {format_packet_summary(pkt)}")

    try:
        kwargs = {
            "prn": packet_callback,
            "filter": bpf_filter,
            "store": True if pcap_file else False
        }
        if interface:
            kwargs["iface"] = interface
        if count > 0:
            kwargs["count"] = count
        if timeout and timeout > 0:
            kwargs["timeout"] = timeout

        packets = sniff(**kwargs)

    except PermissionError:
        print("\n[!] Packet capture requires raw socket privileges. Please run with sudo:\n"
              "  sudo .venv/bin/python scanner.py SNIFF ...")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    total_captured = len(captured)
    print("\n" + "=" * 80)
    print(f"[*] Sniffing session stopped. Captured {total_captured} packet(s).")

    if pcap_file and captured:
        wrpcap(pcap_file, captured)
        print(f"[+] Saved {total_captured} packet(s) to PCAP file: {pcap_file}")
    print("=" * 80)
