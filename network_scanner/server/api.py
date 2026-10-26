"""
Lightweight Embedded Web Application & REST API Server.
Zero third-party dependencies (Built on Python http.server).
Provides REST endpoints and a real-time web dashboard.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from network_scanner.inventory.history import ScanHistoryManager
from network_scanner.inventory.tags import DeviceTagManager
from network_scanner.scanners.ping import execute_ping, ping_sweep
from network_scanner.scanners.tcp import tcp_connect_scan
from network_scanner.scanners.udp import udp_scan
from network_scanner.security.risk import calculate_host_risk
from network_scanner.utils.network import get_local_subnet

WEB_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner Suite - Live Web Dashboard</title>
    <style>
        :root {
            --bg-body: #0b0f19;
            --bg-card: #151d2f;
            --bg-card-hover: #1c263c;
            --border: #243048;
            --text: #f1f5f9;
            --muted: #94a3b8;
            --primary: #0ea5e9;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-body);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 30px 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px;
        }
        h1 { font-size: 24px; color: #fff; display: flex; align-items: center; gap: 10px; }
        .tag-badge { background: rgba(14,165,233,0.15); color: var(--primary); padding: 4px 10px; border-radius: 99px; font-size: 12px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
        .card-label { font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 6px; }
        .card-val { font-size: 26px; font-weight: 700; color: #fff; }
        .action-bar { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
        input, select, button {
            background: var(--bg-card); border: 1px solid var(--border); color: #fff;
            padding: 10px 14px; border-radius: 8px; font-size: 13px; outline: none;
        }
        button { background: var(--primary); font-weight: 600; cursor: pointer; transition: opacity 0.2s; border: none; }
        button:hover { opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
        th { background: #111827; color: var(--muted); padding: 12px 16px; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); }
        td { padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .badge { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; }
        .badge-online { background: rgba(16,185,129,0.15); color: #34d399; }
        .badge-offline { background: rgba(148,163,184,0.15); color: #94a3b8; }
        .table-wrap { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡 Network Scanner Suite <span class="tag-badge">REST API & Dashboard</span></h1>
            <div style="font-size: 12px; color: var(--muted);" id="subnetInfo">Loading subnet...</div>
        </header>

        <div class="grid">
            <div class="card"><div class="card-label">Total Assets Tracked</div><div class="card-val" id="totalAssets">0</div></div>
            <div class="card"><div class="card-label">Active Online</div><div class="card-val" id="onlineAssets" style="color:var(--success);">0</div></div>
            <div class="card"><div class="card-label">Configured Device Tags</div><div class="card-val" id="totalTags">0</div></div>
            <div class="card"><div class="card-label">API Endpoints</div><div class="card-val" style="color:var(--primary);">/api/*</div></div>
        </div>

        <div class="action-bar">
            <input type="text" id="searchInput" placeholder="Search devices by IP, MAC, hostname..." style="flex:1; min-width:240px;" onkeyup="filterTable()">
            <button onclick="refreshData()">🔄 Refresh Assets</button>
        </div>

        <div class="table-wrap">
            <table id="deviceTable">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                        <th>Role / Hostname</th>
                        <th>Times Seen</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody id="deviceRows">
                    <tr><td colspan="6" style="text-align:center; color:var(--muted); padding:24px;">Loading device inventory...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        let devices = [];

        async function loadSubnet() {
            try {
                const res = await fetch('/api/subnet');
                const data = await res.json();
                document.getElementById('subnetInfo').innerText = `Interface: ${data.interface} | Subnet: ${data.cidr} | Gateway: ${data.gateway}`;
            } catch (e) {}
        }

        async function refreshData() {
            try {
                const [invRes, tagsRes] = await Promise.all([
                    fetch('/api/inventory'),
                    fetch('/api/tags')
                ]);
                const invData = await invRes.json();
                const tagsData = await tagsRes.json();

                devices = Object.entries(invData.devices || {}).map(([ip, info]) => ({
                    ip,
                    ...info,
                    tag: tagsData[ip]?.label || ''
                }));

                document.getElementById('totalAssets').innerText = devices.length;
                document.getElementById('onlineAssets').innerText = devices.length;
                document.getElementById('totalTags').innerText = Object.keys(tagsData).length;

                renderTable(devices);
            } catch (e) {
                console.error(e);
            }
        }

        function renderTable(list) {
            const tbody = document.getElementById('deviceRows');
            if (!list.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:24px;">No devices tracked in inventory yet. Run a scan via CLI or API.</td></tr>';
                return;
            }

            tbody.innerHTML = list.map(d => `
                <tr>
                    <td><strong>${d.ip}</strong></td>
                    <td style="font-family:monospace; color:var(--muted);">${d.MAC || '-'}</td>
                    <td>${d.Vendor || '-'}</td>
                    <td>${d.tag ? `<span class="badge" style="background:#0ea5e922; color:#38bdf8;">${d.tag}</span> ` : ''}${d.Hostname || d.DeviceType || '-'}</td>
                    <td>${d.TimesSeen || 1}</td>
                    <td style="color:var(--muted); font-size:12px;">${(d.LastSeen || '').slice(0, 19).replace('T', ' ')}</td>
                </tr>
            `).join('');
        }

        function filterTable() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            const filtered = devices.filter(d => 
                d.ip.toLowerCase().includes(q) ||
                (d.MAC && d.MAC.toLowerCase().includes(q)) ||
                (d.Vendor && d.Vendor.toLowerCase().includes(q)) ||
                (d.Hostname && d.Hostname.toLowerCase().includes(q)) ||
                (d.tag && d.tag.toLowerCase().includes(q))
            );
            renderTable(filtered);
        }

        loadSubnet();
        refreshData();
    </script>
</body>
</html>
"""


class ScannerAPIRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler providing REST endpoints and interactive Web UI."""

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def _send_html(self, html_str, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_str.encode("utf-8"))

    def do_OPTIONS(self):
        self._send_json({"status": "ok"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("", "/dashboard"):
            self._send_html(WEB_DASHBOARD_HTML)
        elif path == "/api/inventory" or path == "/api/hosts":
            history = ScanHistoryManager.load_history()
            self._send_json(history)
        elif path == "/api/tags":
            tags = DeviceTagManager.load_tags()
            self._send_json(tags)
        elif path == "/api/subnet":
            subnet_info = get_local_subnet()
            self._send_json(subnet_info)
        elif path == "/api/help":
            self._send_json({
                "endpoints": {
                    "GET /": "Interactive Web Dashboard",
                    "GET /api/inventory": "Discovered host assets and lifecycle data",
                    "GET /api/tags": "Device friendly tags and notes",
                    "GET /api/subnet": "Local network interface and CIDR subnet",
                    "POST /api/scan/ping": "Run ping probe on target IP/subnet",
                    "POST /api/scan/tcp": "Run TCP port scan on target IP",
                    "POST /api/scan/udp": "Run UDP port scan on target IP",
                    "POST /api/tag": "Save friendly label and notes for an IP"
                }
            })
        else:
            self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b"{}"

        try:
            params = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            params = {}

        if path == "/api/scan/ping":
            target = params.get("target") or get_local_subnet()["cidr"]
            if "/" in target:
                threads = params.get("threads", 30)
                results = ping_sweep(target, max_workers=threads)
            else:
                p_res = execute_ping(target, count=params.get("count", 2))
                results = [p_res]
            self._send_json({"target": target, "results": results})

        elif path == "/api/scan/tcp":
            ip = params.get("ip")
            if not ip:
                self._send_json({"error": "Missing 'ip' parameter"}, status=400)
                return
            ports = params.get("ports", [21, 22, 80, 443, 3306, 8080])
            results = tcp_connect_scan(ip, ports, timeout=params.get("timeout", 0.6))
            risk = calculate_host_risk(results)
            self._send_json({"ip": ip, "open_ports": results, "risk": risk})

        elif path == "/api/scan/udp":
            ip = params.get("ip")
            if not ip:
                self._send_json({"error": "Missing 'ip' parameter"}, status=400)
                return
            ports = params.get("ports", [53, 123, 161, 5353])
            results = udp_scan(ip, ports, timeout=params.get("timeout", 1.5))
            self._send_json({"ip": ip, "responsive_ports": results})

        elif path == "/api/tag":
            target = params.get("target")
            label = params.get("label")
            notes = params.get("notes", "")
            if not target or not label:
                self._send_json({"error": "Missing 'target' or 'label'"}, status=400)
                return
            DeviceTagManager.set_tag(target, label, notes)
            self._send_json({"status": "saved", "target": target, "label": label})

        else:
            self._send_json({"error": "Unknown POST endpoint"}, status=404)


def start_server(host="127.0.0.1", port=8080):
    """Starts the embedded HTTP web server and API daemon."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, ScannerAPIRequestHandler)
    print("\n" + "=" * 75)
    print(f"[*] Network Scanner Suite Web Dashboard & REST API Running!")
    print(f"[*] Dashboard URL:  http://{host}:{port}/")
    print(f"[*] REST Endpoints: http://{host}:{port}/api/inventory")
    print(f"[*] API Help:       http://{host}:{port}/api/help")
    print(f"[*] Press Ctrl+C to terminate server.")
    print("=" * 75 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")
        httpd.server_close()
