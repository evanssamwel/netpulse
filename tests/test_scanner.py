"""
Unit test suite for Network Scanner Suite v2.0.
Uses Python standard unittest framework (zero external test dependencies required).
"""

import unittest
from network_scanner.fingerprint.device_type import classify_device
from network_scanner.fingerprint.services import (
    parse_ftp_banner,
    parse_http_banner,
    parse_mysql_handshake,
    parse_redis_response,
    parse_ssh_banner,
)
from network_scanner.fingerprint.ttl import fingerprint_os_from_ttl
from network_scanner.reports.topology import generate_topology_svg
from network_scanner.scanners.smb import build_smb1_negotiate_packet, build_smb2_negotiate_packet
from network_scanner.scanners.snmp import build_snmp_get_packet, encode_oid
from network_scanner.security.cve import audit_host_vulnerabilities, lookup_cves
from network_scanner.security.risk import calculate_host_risk, calculate_network_risk
from network_scanner import __version__
from network_scanner.utils.network import int2ip, resolve_mac_vendor


class TestVersion(unittest.TestCase):
    def test_version_format(self):
        parts = __version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts))
        self.assertEqual(__version__, "2.3.1")


class TestNetworkUtilities(unittest.TestCase):
    def test_int2ip(self):
        self.assertEqual(int2ip(2130706433), "127.0.0.1")
        self.assertEqual(int2ip(0), "0.0.0.0")

    def test_resolve_mac_vendor_randomized(self):
        # 0x02 locally-administered bit set (e.g., e2:...)
        vendor = resolve_mac_vendor("e2:d5:77:aa:a9:73")
        self.assertEqual(vendor, "Randomized / Private MAC")


class TestFingerprinting(unittest.TestCase):
    def test_fingerprint_os_from_ttl(self):
        os_guess, hops = fingerprint_os_from_ttl(64)
        self.assertIn("Linux", os_guess)
        self.assertEqual(hops, 0)

        os_guess, hops = fingerprint_os_from_ttl(128)
        self.assertIn("Windows", os_guess)
        self.assertEqual(hops, 0)

        os_guess, hops = fingerprint_os_from_ttl(255)
        self.assertIn("Cisco", os_guess)
        self.assertEqual(hops, 0)

    def test_parse_ssh_banner(self):
        service, ver = parse_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        self.assertEqual(service, "SSH")
        self.assertIn("OpenSSH 8.9p1", ver)

    def test_parse_http_banner(self):
        headers = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n<title>Welcome</title>"
        service, ver = parse_http_banner(headers)
        self.assertEqual(service, "HTTP")
        self.assertIn("nginx/1.24.0", ver)
        self.assertIn("Welcome", ver)

    def test_parse_ftp_banner(self):
        service, ver = parse_ftp_banner("220 (vsFTPd 3.0.3)\r\n")
        self.assertEqual(service, "FTP")
        self.assertEqual(ver, "vsFTPd 3.0.3")

    def test_parse_redis_response(self):
        info = "# Server\r\nredis_version:7.2.4\r\n"
        service, ver = parse_redis_response(info)
        self.assertEqual(service, "Redis")
        self.assertEqual(ver, "Redis 7.2.4")


class TestDeviceClassification(unittest.TestCase):
    def test_gateway_classification(self):
        dtype, conf, details = classify_device("192.168.1.1", is_gateway=True)
        self.assertEqual(dtype, "Router / Gateway")

    def test_printer_classification(self):
        dtype, conf, details = classify_device("192.168.1.50", open_ports=[9100, 80], vendor="Hewlett Packard")
        self.assertIn("Printer", dtype)

    def test_nas_classification(self):
        dtype, conf, details = classify_device("192.168.1.20", hostname="synology-nas", open_ports=[5000, 445])
        self.assertIn("NAS", dtype)

    def test_mobile_classification(self):
        dtype, conf, details = classify_device("192.168.1.15", hostname="Galaxy-S24", ttl=64)
        self.assertIn("Mobile", dtype)


class TestSecurityRiskScoring(unittest.TestCase):
    def test_clean_host(self):
        risk = calculate_host_risk([443])
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], "CLEAN")

    def test_telnet_ftp_risk(self):
        risk = calculate_host_risk([21, 23])
        # Telnet 35 + FTP 25 = 60
        self.assertGreaterEqual(risk["score"], 60)
        self.assertIn(risk["level"], ("HIGH", "CRITICAL"))
        self.assertTrue(any("Telnet" in r for r in risk["recommendations"]))
        self.assertTrue(any("FTP" in r for r in risk["recommendations"]))

    def test_network_risk(self):
        hosts = [
            {"OpenPorts": [80]},
            {"OpenPorts": [23, 3306]}
        ]
        net_risk = calculate_network_risk(hosts)
        self.assertGreater(net_risk["network_score"], 0)


class TestCVELookup(unittest.TestCase):
    def test_apache_cve(self):
        matches = lookup_cves("HTTP", "Apache/2.4.49 (Unix)")
        self.assertTrue(any(c["cve"] == "CVE-2021-41773" for c in matches))

    def test_regresshion_cve(self):
        matches = lookup_cves("SSH", "OpenSSH 8.9p1 Ubuntu")
        self.assertTrue(any(c["cve"] == "CVE-2024-6387" for c in matches))

    def test_vsftpd_backdoor_cve(self):
        matches = lookup_cves("FTP", "vsftpd 2.3.4")
        self.assertTrue(any(c["cve"] == "CVE-2011-2523" for c in matches))

    def test_audit_host_vulnerabilities(self):
        ports = [{"service": "FTP", "version": "vsftpd 2.3.4"}]
        res = audit_host_vulnerabilities(ports)
        self.assertTrue(res["has_critical"])
        self.assertEqual(res["max_cvss"], 9.8)


class TestProtocolEngines(unittest.TestCase):
    def test_snmp_packet_builder(self):
        pkt = build_snmp_get_packet("public", "1.3.6.1.2.1.1.1.0")
        self.assertTrue(len(pkt) > 20)
        self.assertEqual(pkt[0], 0x30)  # ASN.1 SEQUENCE

    def test_smb_packet_builders(self):
        smb1_pkt = build_smb1_negotiate_packet()
        self.assertIn(b"\xffSMB", smb1_pkt)

        smb2_pkt = build_smb2_negotiate_packet()
        self.assertIn(b"\xfeSMB", smb2_pkt)

    def test_topology_svg(self):
        devices = [
            {"IP": "192.168.1.1", "Vendor": "Huawei", "DeviceType": "Router / Gateway", "Status": "ONLINE"},
            {"IP": "192.168.1.10", "Hostname": "desktop-pc", "DeviceType": "Desktop / Workstation", "Status": "ONLINE"}
        ]
        svg = generate_topology_svg(devices, gateway_ip="192.168.1.1")
        self.assertIn("<svg", svg)
        self.assertIn("ROUTER / GATEWAY", svg)
        self.assertIn("192.168.1.1", svg)


class TestGeolocation(unittest.TestCase):
    def test_is_public_ip(self):
        from network_scanner.utils.geo import format_geo_banner, get_ip_geolocation, is_public_ip
        # Private IPs
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("10.0.0.5"))
        self.assertFalse(is_public_ip("172.16.5.10"))
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("invalid_ip"))

        # Public IPs
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("1.1.1.1"))

    def test_private_geolocation(self):
        from network_scanner.utils.geo import get_ip_geolocation
        res = get_ip_geolocation("192.168.1.254")
        self.assertEqual(res["status"], "private")

    def test_format_geo_banner(self):
        from network_scanner.utils.geo import format_geo_banner
        mock_data = {
            "status": "success",
            "query": "8.8.8.8",
            "city": "Mountain View",
            "regionName": "California",
            "country": "United States",
            "countryCode": "US",
            "lat": 37.4056,
            "lon": -122.0775,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
            "org": "Google LLC",
            "as": "AS15169 Google LLC"
        }
        banner = format_geo_banner(mock_data)
        self.assertIn("Geolocation & WAN Intelligence", banner)
        self.assertIn("Mountain View", banner)
        self.assertIn("AS15169", banner)


class TestWirelessScanner(unittest.TestCase):
    def test_signal_bars(self):
        from network_scanner.scanners.wifi import _format_signal_bar
        self.assertEqual(_format_signal_bar(100), "[████]")
        self.assertEqual(_format_signal_bar(75), "[████]")
        self.assertEqual(_format_signal_bar(55), "[███ ]")
        self.assertEqual(_format_signal_bar(30), "[██  ]")
        self.assertEqual(_format_signal_bar(10), "[█   ]")
        self.assertEqual(_format_signal_bar(0), "[    ]")


class TestDNSRecon(unittest.TestCase):
    def test_pack_dns_query(self):
        from network_scanner.scanners.dns import build_dns_query
        pkt = build_dns_query("example.com", 1)  # Type A
        self.assertTrue(len(pkt) > 12)
        # Check standard query flags \x01\x00
        self.assertEqual(pkt[2:4], b"\x01\x00")
        # Check qdcount is 1
        self.assertEqual(pkt[4:6], b"\x00\x01")


class TestConfiguration(unittest.TestCase):
    def test_config_defaults(self):
        from network_scanner.core.config import load_config
        cfg = load_config()
        self.assertIn("threads", cfg)
        self.assertIn("timeout", cfg)
        self.assertIn("html_theme", cfg)


class TestHistoryAndTags(unittest.TestCase):
    def test_tag_manager(self):
        import os
        from network_scanner.inventory.tags import DeviceTagManager
        test_ip = "192.0.2.123"
        DeviceTagManager.set_tag(test_ip, "Unit Test Device", "Testing note")
        retrieved = DeviceTagManager.get_tag(test_ip)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["label"], "Unit Test Device")
        self.assertEqual(retrieved["notes"], "Testing note")

        # Clean up
        DeviceTagManager.delete_tag(test_ip)
        self.assertIsNone(DeviceTagManager.get_tag(test_ip))


class TestHTMLReports(unittest.TestCase):
    def test_generate_html_report_multi_theme(self):
        import os
        import tempfile
        from network_scanner.reports.html_report import generate_html_report

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            path = tf.name

        try:
            generate_html_report(
                title="Test Report",
                scan_type="TEST",
                target="192.168.1.0/24",
                stats={"Total": 1},
                items=[{"IP": "192.168.1.1", "Status": "ONLINE", "Role": "Router"}],
                output_path=path,
                theme="cyberpunk"
            )
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn('data-theme="cyberpunk"', content)
            self.assertIn("Cyberpunk Neon", content)
            self.assertIn("192.168.1.1", content)
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestRemediation(unittest.TestCase):
    def test_isolation_rules(self):
        from network_scanner.security.remediation import generate_isolation_rules
        rules = generate_isolation_rules("192.168.1.99")
        self.assertEqual(len(rules), 3)
        self.assertTrue(any("DROP" in r and "192.168.1.99" in r for r in rules))

    def test_export_script(self):
        import os
        import tempfile
        from network_scanner.security.remediation import export_remediation_script

        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as tf:
            path = tf.name

        try:
            export_remediation_script(["192.168.1.100", "192.168.1.101"], output_file=path)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("192.168.1.100", content)
            self.assertIn("192.168.1.101", content)
            self.assertIn("iptables", content)
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()

