"""
Pure-Python SMB / NetBIOS Enumerator.
Performs SMB protocol negotiation, signing policy audit, and NTLMSSP Target Info inspection
without requiring credentials or brute force.
Zero external dependencies.
"""

import socket
import struct
import time


def parse_ntlmssp_target_info(target_info_bytes):
    """Parses AV_PAIR structures from NTLMSSP Challenge Target Info."""
    info = {
        "nb_computer": "",
        "nb_domain": "",
        "dns_computer": "",
        "dns_domain": "",
        "os_version": ""
    }
    offset = 0
    while offset + 4 <= len(target_info_bytes):
        av_id, av_len = struct.unpack("<HH", target_info_bytes[offset:offset + 4])
        offset += 4
        if av_id == 0:  # MsvAvEOL
            break
        val = target_info_bytes[offset:offset + av_len]
        offset += av_len

        try:
            val_str = val.decode("utf-16le")
        except Exception:
            val_str = str(val)

        if av_id == 1:    # MsvAvNbComputerName
            info["nb_computer"] = val_str
        elif av_id == 2:  # MsvAvNbDomainName
            info["nb_domain"] = val_str
        elif av_id == 3:  # MsvAvDnsComputerName
            info["dns_computer"] = val_str
        elif av_id == 4:  # MsvAvDnsDomainName
            info["dns_domain"] = val_str
        elif av_id == 7:  # MsvAvTimestamp
            pass

    return info


def build_smb2_negotiate_packet():
    """Crafts an SMB2 Negotiate Protocol Request."""
    # NetBIOS Session Service Header (4 bytes): \x00 + 3 bytes length
    # SMB2 Header (64 bytes):
    # ProtocolId: \xfeSMB
    # StructureSize: 64
    # CreditCharge: 0
    # ChannelSequence: 0
    # Reserved: 0
    # Command: 0x0000 (NEGOTIATE)
    # CreditsRequested: 31
    # Flags: 0
    # NextCommand: 0
    # MessageId: 0
    # ProcessId: 0xFEFF
    # TreeId: 0
    # SessionId: 0
    # Signature: 16 nulls
    smb2_header = bytearray(64)
    smb2_header[0:4] = b"\xfeSMB"
    struct.pack_into("<H", smb2_header, 4, 64)   # Header size
    struct.pack_into("<H", smb2_header, 12, 0)   # Command: Negotiate
    struct.pack_into("<H", smb2_header, 14, 31)  # Credits
    struct.pack_into("<I", smb2_header, 28, 0xFEFF)  # PID

    # SMB2 Negotiate Request Body:
    # StructureSize: 36 (0x0024)
    # DialectCount: 4
    # SecurityMode: 0x01 (Signing enabled)
    # Reserved: 0
    # Capabilities: 0
    # ClientGuid: 16 random/null bytes
    # ClientStartTime: 0
    # Dialects: 0x0202 (2.0.2), 0x0210 (2.1), 0x0300 (3.0), 0x0302 (3.0.2), 0x0311 (3.1.1)
    body = bytearray()
    body.extend(struct.pack("<H", 36))  # StructureSize
    body.extend(struct.pack("<H", 5))   # 5 dialects
    body.extend(struct.pack("<H", 1))   # Security mode
    body.extend(struct.pack("<H", 0))   # Reserved
    body.extend(struct.pack("<I", 0x7F))  # Capabilities
    body.extend(b"\x12\x34\x56\x78" * 4)  # Client GUID
    body.extend(b"\x00" * 8)              # ClientStartTime
    # Dialects
    body.extend(struct.pack("<H", 0x0202))
    body.extend(struct.pack("<H", 0x0210))
    body.extend(struct.pack("<H", 0x0300))
    body.extend(struct.pack("<H", 0x0302))
    body.extend(struct.pack("<H", 0x0311))

    total_smb = bytes(smb2_header) + bytes(body)
    netbios_header = struct.pack("!I", len(total_smb))
    return netbios_header + total_smb


def build_smb1_negotiate_packet():
    """Crafts an SMBv1 Negotiate Protocol Request offering multiple dialects."""
    # NetBIOS Header (4 bytes)
    # SMBv1 Header (32 bytes)
    header = bytearray(32)
    header[0:4] = b"\xffSMB"
    header[4] = 0x72  # SMB_COM_NEGOTIATE
    header[9] = 0x18  # Flags
    struct.pack_into("<H", header, 10, 0xC853)  # Flags2
    struct.pack_into("<H", header, 26, 0xFEFF)  # PID

    dialects = [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"NT LM 0.12", b"SMB 2.002", b"SMB 2.???"]
    body = bytearray([0x00])  # WordCount
    byte_count_pos = len(body)
    body.extend(b"\x00\x00")  # Placeholder for ByteCount

    for d in dialects:
        body.append(0x02)  # Buffer format: Dialect string
        body.extend(d + b"\x00")

    struct.pack_into("<H", body, byte_count_pos, len(body) - 3)
    total_smb = bytes(header) + bytes(body)
    return struct.pack("!I", len(total_smb)) + total_smb


DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1"
}


def enumerate_smb(ip, port=445, timeout=2.0):
    """
    Connects to target SMB service and enumerates supported versions,
    signing enforcement, and server identity.

    Returns:
        dict: SMB audit findings or None if inaccessible.
    """
    result = {
        "ip": ip,
        "port": port,
        "smbv1_enabled": False,
        "selected_dialect": "Unknown",
        "signing_required": False,
        "signing_enabled": False,
        "netbios_computer": "",
        "netbios_domain": "",
        "dns_computer": "",
        "dns_domain": "",
        "warnings": []
    }

    # Step 1: Probe with SMBv1 Negotiate to check if legacy SMBv1 is enabled
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(build_smb1_negotiate_packet())
            resp = s.recv(1024)
            if len(resp) >= 8 and resp[4:8] == b"\xffSMB":
                # Check chosen dialect index
                if len(resp) > 36:
                    dialect_idx = struct.unpack("<H", resp[37:39])[0]
                    # If it didn't reject (0xFFFF), and accepted an SMB1 dialect
                    if dialect_idx != 0xFFFF:
                        result["smbv1_enabled"] = True
                        result["warnings"].append("SMBv1 is active! Critical risk for EternalBlue (MS17-010) and ransomware.")
    except Exception:
        pass

    # Step 2: Probe with SMB2/3 Negotiate
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(build_smb2_negotiate_packet())
            resp = s.recv(2048)

            if len(resp) >= 8 and resp[4:8] == b"\xfeSMB":
                # SMB2 Header is 64 bytes (starting at byte 4)
                # Response body starts at byte 68
                if len(resp) >= 72:
                    sec_mode = resp[70]
                    result["signing_enabled"] = bool(sec_mode & 0x01)
                    result["signing_required"] = bool(sec_mode & 0x02)

                    dialect = struct.unpack("<H", resp[72:74])[0]
                    result["selected_dialect"] = DIALECT_NAMES.get(dialect, f"SMB Dialect 0x{dialect:04x}")

                    if not result["signing_required"]:
                        result["warnings"].append("SMB Message Signing is NOT required! Target is vulnerable to NTLM Relay attacks.")
                    else:
                        result["signing_status"] = "Enforced / Required (Secure against Relay)"

                    # If server sent security buffer (NTLMSSP Negotiate challenge)
                    sec_buf_offset = struct.unpack("<H", resp[76:78])[0]
                    sec_buf_len = struct.unpack("<H", resp[78:80])[0]

                    if sec_buf_offset and sec_buf_len:
                        buf_start = 4 + sec_buf_offset
                        buf = resp[buf_start:buf_start + sec_buf_len]
                        ntlmssp_pos = buf.find(b"NTLMSSP\x00")
                        if ntlmssp_pos != -1:
                            challenge_data = buf[ntlmssp_pos:]
                            # Check if Target Info present in NTLMSSP Challenge (Type 2)
                            if len(challenge_data) >= 48 and challenge_data[8] == 2:
                                ti_len, _, ti_offset = struct.unpack("<HHI", challenge_data[40:48])
                                if ti_offset + ti_len <= len(challenge_data):
                                    ti_bytes = challenge_data[ti_offset:ti_offset + ti_len]
                                    target_info = parse_ntlmssp_target_info(ti_bytes)
                                    result["netbios_computer"] = target_info.get("nb_computer", "")
                                    result["netbios_domain"] = target_info.get("nb_domain", "")
                                    result["dns_computer"] = target_info.get("dns_computer", "")
                                    result["dns_domain"] = target_info.get("dns_domain", "")

                return result
    except Exception:
        pass

    return result if (result["smbv1_enabled"] or result["selected_dialect"] != "Unknown") else None
