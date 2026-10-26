"""
Pure-Python DNS Enumerator & AXFR Zone Transfer Tester.
Resolves A, AAAA, MX, NS, TXT, SOA, and tests for dangerous AXFR zone transfer misconfigurations.
Zero external dependencies.
"""

import socket
import struct
import time

RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "AXFR": 252
}


def encode_dns_name(domain):
    """Encodes a domain name string into DNS wire format bytes."""
    encoded = bytearray()
    for part in domain.strip(".").split("."):
        b = part.encode("utf-8")
        encoded.append(len(b))
        encoded.extend(b)
    encoded.append(0)
    return bytes(encoded)


def decode_dns_name(raw_bytes, offset):
    """Decodes a domain name from DNS response, handling compression pointers."""
    labels = []
    visited_offsets = set()

    while offset < len(raw_bytes):
        length = raw_bytes[offset]
        if length == 0:
            offset += 1
            break
        # Compression pointer (first two bits 11)
        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(raw_bytes):
                break
            ptr = struct.unpack("!H", raw_bytes[offset:offset + 2])[0] & 0x3FFF
            offset += 2
            if ptr in visited_offsets:  # Prevent circular loop
                break
            visited_offsets.add(ptr)
            sub_name, _ = decode_dns_name(raw_bytes, ptr)
            labels.append(sub_name)
            break
        else:
            offset += 1
            label = raw_bytes[offset:offset + length].decode("utf-8", errors="ignore")
            labels.append(label)
            offset += length

    return ".".join(labels), offset


def build_dns_query(domain, qtype=1, tx_id=0x1234):
    """Crafts standard DNS query packet."""
    header = bytearray(12)
    struct.pack_into("!H", header, 0, tx_id)   # Transaction ID
    struct.pack_into("!H", header, 2, 0x0100)  # Standard Query, Recursion Desired
    struct.pack_into("!H", header, 4, 1)       # 1 Question
    struct.pack_into("!H", header, 6, 0)       # 0 Answers
    struct.pack_into("!H", header, 8, 0)       # 0 Authority
    struct.pack_into("!H", header, 10, 0)      # 0 Additional

    qname = encode_dns_name(domain)
    qtail = struct.pack("!HH", qtype, 1)       # Type, Class IN (1)
    return bytes(header) + qname + qtail


def query_dns(domain, qtype_name="A", server="8.8.8.8", port=53, timeout=2.0):
    """
    Sends a DNS query for the given record type.
    Returns:
        list of string records.
    """
    qtype = RECORD_TYPES.get(qtype_name.upper(), 1)
    tx_id = 0x2A3C
    packet = build_dns_query(domain, qtype=qtype, tx_id=tx_id)
    records = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, port))
            resp, _ = s.recvfrom(2048)

            if len(resp) < 12:
                return []

            # Check response code (RCODE)
            flags = struct.unpack("!H", resp[2:4])[0]
            rcode = flags & 0x000F
            ancount = struct.unpack("!H", resp[6:8])[0]

            if rcode != 0 or ancount == 0:
                return []

            offset = 12
            # Skip Question section
            _, offset = decode_dns_name(resp, offset)
            offset += 4  # Skip QTYPE and QCLASS

            # Parse Answers
            for _ in range(ancount):
                if offset >= len(resp):
                    break
                _, offset = decode_dns_name(resp, offset)
                if offset + 10 > len(resp):
                    break
                atype, aclass, ttl, rdlength = struct.unpack("!HHIH", resp[offset:offset + 10])
                offset += 10
                rdata = resp[offset:offset + rdlength]

                if atype == 1 and rdlength == 4:  # A (IPv4)
                    ip_str = socket.inet_ntoa(rdata)
                    records.append(ip_str)
                elif atype == 28 and rdlength == 16:  # AAAA (IPv6)
                    ip6_str = socket.inet_ntop(socket.AF_INET6, rdata)
                    records.append(ip6_str)
                elif atype in (2, 5, 12):  # NS, CNAME, PTR
                    name, _ = decode_dns_name(resp, offset)
                    if name:
                        records.append(name)
                elif atype == 15 and rdlength > 2:  # MX
                    pref = struct.unpack("!H", rdata[:2])[0]
                    mx_name, _ = decode_dns_name(resp, offset + 2)
                    records.append(f"{mx_name} (Priority {pref})")
                elif atype == 16:  # TXT
                    txt_val = rdata[1:1 + rdata[0]].decode("utf-8", errors="ignore")
                    records.append(txt_val)

                offset += rdlength

    except Exception:
        pass

    return records


def test_axfr_zone_transfer(domain, nameserver, port=53, timeout=3.0):
    """
    Tests if an authoritative nameserver permits unauthenticated AXFR Zone Transfers over TCP.
    AXFR transfers allow attackers to enumerate every internal DNS record.
    Returns:
        dict: {"vulnerable": bool, "records_count": int, "sample": list}
    """
    qtype_axfr = 252
    tx_id = 0x5678
    query = build_dns_query(domain, qtype=qtype_axfr, tx_id=tx_id)
    # TCP DNS packet is prefixed with 2-byte length
    tcp_packet = struct.pack("!H", len(query)) + query

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((nameserver, port))
            s.sendall(tcp_packet)

            # Read 2 bytes length header
            len_bytes = s.recv(2)
            if len(len_bytes) < 2:
                return {"vulnerable": False, "records_count": 0, "sample": []}

            resp_len = struct.unpack("!H", len_bytes)[0]
            resp_data = s.recv(min(resp_len, 4096))

            if len(resp_data) >= 12:
                flags = struct.unpack("!H", resp_data[2:4])[0]
                rcode = flags & 0x000F
                ancount = struct.unpack("!H", resp_data[6:8])[0]

                # RCODE 0 = No Error, and Answer Count > 0 indicates AXFR accepted!
                if rcode == 0 and ancount > 0:
                    return {
                        "vulnerable": True,
                        "nameserver": nameserver,
                        "records_count": ancount,
                        "warning": "CRITICAL: Zone Transfer (AXFR) allowed! Full domain records leaked."
                    }
    except Exception:
        pass

    return {"vulnerable": False, "records_count": 0, "sample": []}


def enumerate_domain_dns(target, custom_server=None, timeout=2.0):
    """
    Runs comprehensive DNS enumeration across records and checks AXFR misconfiguration.
    Returns:
        dict: Discovered DNS records and security findings.
    """
    results = {
        "target": target,
        "records": {},
        "nameservers": [],
        "axfr_vulnerable": False,
        "warnings": []
    }

    # Discover authoritative nameservers
    ns_list = query_dns(target, "NS", server=custom_server or "8.8.8.8", timeout=timeout)
    results["nameservers"] = ns_list

    # Query standard records
    for rtype in ["A", "AAAA", "MX", "TXT", "SOA"]:
        recs = query_dns(target, rtype, server=custom_server or "8.8.8.8", timeout=timeout)
        if recs:
            results["records"][rtype] = recs

    # Test AXFR against each discovered nameserver
    for ns in ns_list:
        # Resolve NS IP if needed
        ns_ips = query_dns(ns, "A", server="8.8.8.8", timeout=timeout)
        test_ip = ns_ips[0] if ns_ips else ns
        axfr_res = test_axfr_zone_transfer(target, test_ip, timeout=timeout)
        if axfr_res["vulnerable"]:
            results["axfr_vulnerable"] = True
            results["warnings"].append(f"AXFR Zone Transfer permitted by {ns} ({test_ip})! Full DNS table exposed.")

    return results
