"""
Pure-Python SNMP v1/v2c Enumeration Engine.
Queries MIB-II system information (sysDescr, sysName, sysUptime, sysLocation, sysContact).
Zero external dependencies.
"""

import socket
import struct
import time


def encode_asn1_length(length):
    """Encodes length in ASN.1 BER format."""
    if length < 0x80:
        return bytes([length])
    len_bytes = []
    while length > 0:
        len_bytes.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(len_bytes)]) + bytes(len_bytes)


def encode_oid(oid_str):
    """Encodes a dotted decimal OID string into ASN.1 BER bytes."""
    parts = [int(p) for p in oid_str.strip(".").split(".")]
    if len(parts) < 2:
        return b""
    # First byte is (X * 40) + Y
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        sub_bytes = []
        val = part
        sub_bytes.append(val & 0x7F)
        val >>= 7
        while val > 0:
            sub_bytes.insert(0, (val & 0x7F) | 0x80)
            val >>= 7
        encoded.extend(sub_bytes)
    return bytes([0x06, len(encoded)]) + bytes(encoded)


def build_snmp_get_packet(community, oid_str, request_id=1):
    """Crafts an SNMP v2c GetRequest packet."""
    oid_bytes = encode_oid(oid_str)
    # VarBind: SEQUENCE { ObjectName (OID), ObjectSyntax (NULL: 0x05 0x00) }
    varbind_val = oid_bytes + b"\x05\x00"
    varbind = b"\x30" + encode_asn1_length(len(varbind_val)) + varbind_val
    # VarBindList: SEQUENCE OF VarBind
    varbind_list = b"\x30" + encode_asn1_length(len(varbind)) + varbind

    # GetRequest-PDU (0xA0): SEQUENCE { request-id, error-status (0), error-index (0), varbind_list }
    req_id_bytes = b"\x02\x04" + struct.pack("!I", request_id)
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"
    pdu_content = req_id_bytes + error_status + error_index + varbind_list
    pdu = b"\xA0" + encode_asn1_length(len(pdu_content)) + pdu_content

    # SNMP Message: SEQUENCE { version (1 for v2c), community, pdu }
    version_bytes = b"\x02\x01\x01"  # 1 = SNMPv2c (0 = v1)
    comm_bytes = community.encode("utf-8")
    community_encoded = b"\x04" + encode_asn1_length(len(comm_bytes)) + comm_bytes

    msg_content = version_bytes + community_encoded + pdu
    return b"\x30" + encode_asn1_length(len(msg_content)) + msg_content


def decode_asn1_tlv(raw_bytes, offset=0):
    """Helper to decode a single ASN.1 TLV (Type, Length, Value) starting at offset."""
    if offset >= len(raw_bytes):
        return None, 0, offset
    tag = raw_bytes[offset]
    offset += 1
    if offset >= len(raw_bytes):
        return None, 0, offset

    first_len = raw_bytes[offset]
    offset += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_len_bytes = first_len & 0x7F
        length = 0
        for _ in range(num_len_bytes):
            if offset < len(raw_bytes):
                length = (length << 8) | raw_bytes[offset]
                offset += 1

    value = raw_bytes[offset:offset + length]
    return tag, value, offset + length


def decode_snmp_response_string(raw_bytes):
    """Extracts the first printable string or value from an SNMP response packet."""
    try:
        # Scan for OCTET STRING (0x04) or TimeTicks (0x43) in response
        idx = 0
        while idx < len(raw_bytes):
            tag, val, next_idx = decode_asn1_tlv(raw_bytes, idx)
            if tag == 0x04 and len(val) > 0:  # OCTET STRING
                text = val.decode("utf-8", errors="ignore").strip()
                if any(c.isalnum() for c in text):
                    return text
            elif tag == 0x43 and len(val) > 0:  # TimeTicks
                ticks = int.from_bytes(val, byteorder="big")
                seconds = ticks // 100
                hours = seconds // 3600
                mins = (seconds % 3600) // 60
                secs = seconds % 60
                return f"{hours}h {mins}m {secs}s ({ticks} ticks)"
            elif tag in (0x30, 0xA2):  # SEQUENCE or Response-PDU
                idx += 2 if len(raw_bytes) > idx + 1 and raw_bytes[idx + 1] < 0x80 else 3
                continue
            idx = next_idx
    except Exception:
        pass
    return ""


STANDARD_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0"
}


def query_snmp_oid(ip, oid_str, community="public", port=161, timeout=1.5):
    """Queries a single SNMP OID and returns the decoded string response."""
    packet = build_snmp_get_packet(community, oid_str)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, port))
            data, _ = s.recvfrom(4096)
            return decode_snmp_response_string(data)
    except Exception:
        return ""


def enumerate_snmp(ip, communities=None, port=161, timeout=1.5):
    """
    Performs full MIB-II SNMP enumeration against target.
    Tests common community strings if not specified.

    Returns:
        dict: Discovered system metrics and status.
    """
    if communities is None:
        communities = ["public", "private", "community", "internal"]

    valid_community = None
    results = {}

    for comm in communities:
        descr = query_snmp_oid(ip, STANDARD_OIDS["sysDescr"], community=comm, port=port, timeout=timeout)
        if descr:
            valid_community = comm
            results["sysDescr"] = descr
            break

    if not valid_community:
        return None

    results["community"] = valid_community
    for name, oid in STANDARD_OIDS.items():
        if name not in results:
            val = query_snmp_oid(ip, oid, community=valid_community, port=port, timeout=timeout)
            if val:
                results[name] = val

    return results
