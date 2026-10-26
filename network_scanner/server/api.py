"""
Lightweight Embedded Web Application & REST API Server.
Zero third-party dependencies (Built on Python standard http.server).
Provides interactive GUI operations and complete REST API endpoints for all scanner features.
"""

import csv
import io
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from network_scanner.inventory.history import ScanHistoryManager
from network_scanner.inventory.tags import DeviceTagManager
from network_scanner.scanners.dns import enumerate_domain_dns
from network_scanner.scanners.ping import execute_ping, ping_sweep
from network_scanner.scanners.tcp import tcp_connect_scan, tcp_syn_scan
from network_scanner.scanners.udp import udp_scan
from network_scanner.scanners.wifi import get_wireless_interfaces, scan_wifi
from network_scanner.security.cve import lookup_cves
from network_scanner.security.remediation import generate_isolation_rules, isolate_device
from network_scanner.security.risk import calculate_host_risk
from network_scanner.utils.geo import get_ip_geolocation, is_public_ip
from network_scanner.utils.network import get_local_subnet, resolve_mac_vendor

WEB_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetPulse Studio - Network Security Suite GUI</title>
    <style>
        :root {
            --bg-body: #0a0e17;
            --bg-surface: #111827;
            --bg-card: #151d2e;
            --bg-card-hover: #1c263c;
            --border: #223049;
            --text: #f1f5f9;
            --muted: #94a3b8;
            --primary: #0ea5e9;
            --primary-hover: #0284c7;
            --primary-glow: rgba(14, 165, 233, 0.25);
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --purple: #a855f7;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body.theme-cyberpunk {
            --bg-body: #05050d;
            --bg-surface: #0e0d1f;
            --bg-card: #14122d;
            --bg-card-hover: #1c183e;
            --border: #3b1d6e;
            --text: #ffffff;
            --muted: #a39bc2;
            --primary: #00f0ff;
            --primary-hover: #00c8d6;
            --primary-glow: rgba(0, 240, 255, 0.35);
            --success: #39ff14;
            --danger: #ff0055;
            --warning: #ffe600;
            --purple: #d946ef;
        }

        body.theme-light {
            --bg-body: #f8fafc;
            --bg-surface: #ffffff;
            --bg-card: #ffffff;
            --bg-card-hover: #f1f5f9;
            --border: #cbd5e1;
            --text: #0f172a;
            --muted: #64748b;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            --primary-glow: rgba(2, 132, 199, 0.15);
            --success: #16a34a;
            --danger: #dc2626;
            --warning: #d97706;
            --purple: #9333ea;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-body);
            color: var(--text);
            font-family: var(--font-family);
            padding: 24px 20px;
            transition: background-color 0.25s, color 0.25s;
            line-height: 1.5;
        }
        .container { max-width: 1260px; margin: 0 auto; }

        /* Top Header */
        header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px;
            flex-wrap: wrap; gap: 16px;
        }
        .brand { display: flex; align-items: center; gap: 12px; }
        .brand-icon {
            width: 44px; height: 44px; border-radius: 12px; background: linear-gradient(135deg, var(--primary), var(--purple));
            display: flex; align-items: center; justify-content: center; font-size: 22px; box-shadow: 0 0 16px var(--primary-glow);
        }
        h1 { font-size: 22px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
        body.theme-light h1 { color: #0f172a; }
        .version-badge {
            background: rgba(14, 165, 233, 0.15); color: var(--primary);
            padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; margin-left: 8px;
        }
        .header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .telemetry-pill {
            display: flex; align-items: center; gap: 8px; background: var(--bg-surface);
            border: 1px solid var(--border); padding: 6px 14px; border-radius: 99px; font-size: 12px; color: var(--muted);
        }
        .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 8px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(1.2); } }

        /* Navigation Tabs */
        .tabs {
            display: flex; gap: 8px; border-bottom: 1px solid var(--border);
            margin-bottom: 24px; overflow-x: auto; padding-bottom: 4px;
        }
        .tab-btn {
            background: transparent; border: none; color: var(--muted); padding: 10px 18px;
            font-size: 13px; font-weight: 600; cursor: pointer; border-radius: 8px 8px 0 0;
            display: flex; align-items: center; gap: 8px; transition: all 0.2s; white-space: nowrap;
            border-bottom: 3px solid transparent;
        }
        .tab-btn:hover { color: var(--text); background: var(--bg-card); }
        .tab-btn.active {
            color: var(--primary); background: var(--bg-surface);
            border-bottom: 3px solid var(--primary);
        }

        /* Metric Grid */
        .grid-kpi {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px; margin-bottom: 24px;
        }
        .kpi-card {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 12px; padding: 18px 20px; transition: transform 0.2s, border-color 0.2s;
        }
        .kpi-card:hover { transform: translateY(-2px); border-color: var(--primary); }
        .kpi-label { font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 700; margin-bottom: 6px; }
        .kpi-val { font-size: 28px; font-weight: 800; color: #fff; }
        body.theme-light .kpi-val { color: #0f172a; }

        /* Tab Content Containers */
        .tab-pane { display: none; }
        .tab-pane.active { display: block; animation: fadeIn 0.25s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        /* Forms, Cards, and Inputs */
        .control-panel {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 12px; padding: 20px; margin-bottom: 24px;
        }
        .panel-title { font-size: 16px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        .form-row { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 14px; align-items: flex-end; }
        .form-group { display: flex; flex-direction: column; gap: 6px; flex: 1; min-width: 200px; }
        label { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; }
        input, select, textarea {
            background: var(--bg-surface); border: 1px solid var(--border); color: var(--text);
            padding: 10px 14px; border-radius: 8px; font-size: 13px; outline: none; transition: border-color 0.2s;
        }
        input:focus, select:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-glow); }
        .btn {
            background: var(--primary); color: #fff; border: none; padding: 10px 18px;
            border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
            display: inline-flex; align-items: center; justify-content: center; gap: 8px;
            transition: all 0.2s; text-decoration: none;
        }
        .btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
        .btn-secondary { background: var(--bg-surface); border: 1px solid var(--border); color: var(--text); }
        .btn-secondary:hover { background: var(--bg-card-hover); border-color: var(--muted); }
        .btn-danger { background: var(--danger); color: #fff; }
        .btn-danger:hover { background: #b91c1c; }
        .btn-sm { padding: 6px 12px; font-size: 11px; border-radius: 6px; }

        /* Tables */
        .table-wrap {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 12px; overflow-x: auto; margin-bottom: 24px;
        }
        table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
        th {
            background: var(--bg-surface); color: var(--muted); padding: 12px 16px;
            font-size: 11px; text-transform: uppercase; font-weight: 700; border-bottom: 1px solid var(--border);
        }
        td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }

        /* Badges */
        .badge {
            display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px;
            border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase;
        }
        .badge-success { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
        .badge-info { background: rgba(14, 165, 233, 0.15); color: #38bdf8; }
        .badge-purple { background: rgba(168, 85, 247, 0.15); color: #c084fc; }

        /* Signal Bar */
        .sig-meter { display: inline-flex; align-items: center; gap: 6px; font-family: monospace; }
        .sig-bar-box { width: 60px; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; display: flex; }
        .sig-fill { height: 100%; border-radius: 4px; }

        /* Terminal & Code Blocks */
        .code-box {
            background: #080c14; border: 1px solid var(--border); border-radius: 8px;
            padding: 14px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px; color: #38bdf8; overflow-x: auto; margin-top: 10px; position: relative;
        }
        body.theme-light .code-box { background: #1e293b; color: #38bdf8; }
        .copy-btn {
            position: absolute; top: 8px; right: 8px; background: rgba(255,255,255,0.1);
            color: #fff; border: none; padding: 4px 8px; font-size: 10px; border-radius: 4px; cursor: pointer;
        }
        .copy-btn:hover { background: rgba(255,255,255,0.25); }

        /* Modal Dialog */
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7);
            display: none; align-items: center; justify-content: center; z-index: 999;
            backdrop-filter: blur(4px);
        }
        .modal-overlay.active { display: flex; }
        .modal-box {
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
            padding: 24px; max-width: 500px; width: 90%; box-shadow: 0 20px 40px rgba(0,0,0,0.6);
        }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }

        /* Toast Notifications */
        #toastContainer {
            position: fixed; bottom: 24px; right: 24px; z-index: 1000;
            display: flex; flex-direction: column; gap: 8px;
        }
        .toast {
            background: var(--bg-surface); border: 1px solid var(--border); color: var(--text);
            padding: 12px 18px; border-radius: 8px; font-size: 13px; box-shadow: 0 10px 25px rgba(0,0,0,0.4);
            display: flex; align-items: center; gap: 10px; animation: slideIn 0.25s ease;
        }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

        /* Loader Spinner */
        .spinner {
            width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff; border-radius: 50%; animation: spin 0.8s linear infinite; display: inline-block;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Risk Gauge */
        .risk-gauge {
            display: flex; align-items: center; gap: 14px; background: var(--bg-surface);
            border: 1px solid var(--border); padding: 14px 18px; border-radius: 10px; margin-bottom: 16px;
        }
        .risk-score-circle {
            width: 52px; height: 52px; border-radius: 50%; display: flex; align-items: center;
            justify-content: center; font-size: 20px; font-weight: 800; color: #fff;
        }
    </style>
</head>
<body class="theme-obsidian">
    <div class="container">
        <!-- Main Suite Header -->
        <header>
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div>
                    <h1>NetPulse Studio <span class="version-badge">v2.4.0 GUI Console</span></h1>
                    <div style="font-size: 12px; color: var(--muted);">Pure Python Network Security Reconnaissance & Audit Engine</div>
                </div>
            </div>

            <div class="header-actions">
                <div class="telemetry-pill">
                    <div class="live-dot"></div>
                    <span id="headerTelemetry">Detecting Network...</span>
                </div>
                <button class="btn btn-secondary btn-sm" onclick="toggleTheme()" id="themeBtn">🌙 Obsidian</button>
            </div>
        </header>

        <!-- Navigation Tabs -->
        <nav class="tabs">
            <button class="tab-btn active" onclick="switchTab('inventory', this)">📊 Assets & Inventory</button>
            <button class="tab-btn" onclick="switchTab('ping', this)">⚡ Subnet Discovery</button>
            <button class="tab-btn" onclick="switchTab('ports', this)">🔍 Port & CVE Audit</button>
            <button class="tab-btn" onclick="switchTab('wifi', this)">📶 Wi-Fi Recon</button>
            <button class="tab-btn" onclick="switchTab('geo', this)">🌍 GeoIP Intel</button>
            <button class="tab-btn" onclick="switchTab('dns', this)">🌐 DNS & AXFR</button>
            <button class="tab-btn" onclick="switchTab('remediation', this)">🛡️ Remediation</button>
        </nav>

        <!-- TAB 1: ASSETS & INVENTORY -->
        <div id="tab-inventory" class="tab-pane active">
            <div class="grid-kpi">
                <div class="kpi-card">
                    <div class="kpi-label">Total Assets Discovered</div>
                    <div class="kpi-val" id="kpiTotalAssets">0</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Active Subnet CIDR</div>
                    <div class="kpi-val" id="kpiSubnet" style="font-size:20px; color:var(--primary);">...</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Tagged Custom Devices</div>
                    <div class="kpi-val" id="kpiTagged" style="color:var(--purple);">0</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Active Network Interface</div>
                    <div class="kpi-val" id="kpiInterface" style="font-size:20px; color:var(--success);">...</div>
                </div>
            </div>

            <div class="control-panel">
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Filter Devices</label>
                        <input type="text" id="invSearchInput" placeholder="Search by IP, MAC, Vendor, Hostname, Tag..." onkeyup="filterInventoryTable()">
                    </div>
                    <div class="form-group">
                        <label>Actions</label>
                        <div style="display:flex; gap:8px;">
                            <button class="btn btn-secondary" onclick="loadInventoryData()">🔄 Refresh</button>
                            <a class="btn btn-secondary" href="/api/export?format=csv" download>📄 Export CSV</a>
                            <a class="btn btn-secondary" href="/api/export?format=json" download>📥 Export JSON</a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Vendor / Manufacturer</th>
                            <th>Role / Custom Label</th>
                            <th>Times Seen</th>
                            <th>Last Seen</th>
                            <th>Quick Actions</th>
                        </tr>
                    </thead>
                    <tbody id="inventoryRows">
                        <tr><td colspan="8" style="text-align:center; padding:24px; color:var(--muted);">Loading network asset inventory...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 2: SUBNET PING SWEEP -->
        <div id="tab-ping" class="tab-pane">
            <div class="control-panel">
                <div class="panel-title">⚡ Subnet Ping Sweep & Host Discovery</div>
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Target Subnet or Single IP</label>
                        <input type="text" id="pingTarget" placeholder="e.g. 192.168.1.0/24 or 10.0.0.1">
                    </div>
                    <div class="form-group">
                        <label>Threads (Concurrency)</label>
                        <input type="number" id="pingThreads" value="30" min="5" max="100">
                    </div>
                    <div class="form-group">
                        <label>Timeout (Sec)</label>
                        <input type="number" id="pingTimeout" value="1.0" step="0.2" min="0.2" max="5.0">
                    </div>
                    <div class="form-group" style="flex:0; min-width:auto;">
                        <label>&nbsp;</label>
                        <button class="btn" id="pingStartBtn" onclick="runPingSweep()">🚀 Launch Ping Sweep</button>
                    </div>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-secondary btn-sm" onclick="setPingPreset('detected')">Auto-Detect Subnet</button>
                    <button class="btn btn-secondary btn-sm" onclick="setPingPreset('gateway')">Target Gateway</button>
                    <button class="btn btn-secondary btn-sm" onclick="setPingPreset('local')">Target Localhost</button>
                </div>
            </div>

            <div class="table-wrap">
                <div style="padding: 12px 16px; border-bottom: 1px solid var(--border); font-size:12px; color:var(--muted);" id="pingSummary">
                    Enter a CIDR subnet and click Launch Ping Sweep to discover active network devices.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Host IP</th>
                            <th>Status</th>
                            <th>Avg Latency (RTT)</th>
                            <th>Packet Loss</th>
                            <th>TTL & OS Guess</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="pingResultsRows">
                        <tr><td colspan="6" style="text-align:center; padding:24px; color:var(--muted);">No scan executed yet.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 3: PORT & VULNERABILITY SCANNER -->
        <div id="tab-ports" class="tab-pane">
            <div class="control-panel">
                <div class="panel-title">🔍 Port & Vulnerability Auditor (TCP / UDP)</div>
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Target Host IP</label>
                        <input type="text" id="portTarget" placeholder="e.g. 192.168.1.1 or 127.0.0.1">
                    </div>
                    <div class="form-group">
                        <label>Protocol Mode</label>
                        <select id="portProtocol">
                            <option value="tcp_connect">TCP Connect (Full Handshake)</option>
                            <option value="udp">UDP Service Probe (DNS/NTP/SNMP)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Timeout (Sec)</label>
                        <input type="number" id="portTimeout" value="0.8" step="0.2" min="0.2" max="5.0">
                    </div>
                    <div class="form-group" style="flex:0; min-width:auto;">
                        <label>&nbsp;</label>
                        <button class="btn" id="portStartBtn" onclick="runPortScan()">🔎 Execute Port Audit</button>
                    </div>
                </div>

                <div class="form-group" style="margin-bottom:14px;">
                    <label>Ports to Scan (Comma-separated)</label>
                    <input type="text" id="portListInput" value="21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443">
                </div>

                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-secondary btn-sm" onclick="setPortPreset('web_remote')">Top 20 Web/Remote</button>
                    <button class="btn btn-secondary btn-sm" onclick="setPortPreset('db')">Database Ports</button>
                    <button class="btn btn-secondary btn-sm" onclick="setPortPreset('web')">Web Servers</button>
                    <button class="btn btn-secondary btn-sm" onclick="setPortPreset('windows')">Windows / SMB</button>
                    <button class="btn btn-secondary btn-sm" onclick="setPortPreset('udp')">Common UDP</button>
                </div>
            </div>

            <!-- Host Risk Gauge -->
            <div id="riskGaugeCard" style="display:none;" class="risk-gauge">
                <div class="risk-score-circle" id="riskCircle" style="background:var(--success);">0</div>
                <div style="flex:1;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <strong style="font-size:15px;" id="riskLevelTitle">Host Risk: Clean</strong>
                        <span class="badge" id="riskBadge">LOW</span>
                    </div>
                    <div style="font-size:12px; color:var(--muted);" id="riskSummaryText">No high-risk services exposed.</div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>State</th>
                            <th>Latency</th>
                            <th>Banner / Version Info</th>
                            <th>CVE Vulnerability Advisories</th>
                        </tr>
                    </thead>
                    <tbody id="portResultsRows">
                        <tr><td colspan="7" style="text-align:center; padding:24px; color:var(--muted);">Select a target and click Execute Port Audit.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 4: WI-FI RECONNAISSANCE -->
        <div id="tab-wifi" class="tab-pane">
            <div class="control-panel">
                <div class="panel-title">📶 Wireless / Wi-Fi Access Point Discovery</div>
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Wireless Interface</label>
                        <select id="wifiInterfaceSelect">
                            <option value="">Auto-Detect Default</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex:0; min-width:auto;">
                        <label>&nbsp;</label>
                        <button class="btn" id="wifiStartBtn" onclick="runWifiScan()">📡 Discover Nearby Wi-Fi</button>
                    </div>
                </div>
                <div style="font-size:12px; color:var(--muted);">
                    Discovers nearby 802.11 Access Points, signal power, channels, and flags insecure (WEP / Open) wireless networks.
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>SSID (Network Name)</th>
                            <th>BSSID (MAC)</th>
                            <th>Signal Quality</th>
                            <th>Channel</th>
                            <th>Security Standard</th>
                            <th>Posture</th>
                        </tr>
                    </thead>
                    <tbody id="wifiResultsRows">
                        <tr><td colspan="6" style="text-align:center; padding:24px; color:var(--muted);">Click Discover Nearby Wi-Fi to scan local airspace.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 5: GEOIP INTEL -->
        <div id="tab-geo" class="tab-pane">
            <div class="control-panel">
                <div class="panel-title">🌍 External IP Geolocation & Threat Intelligence</div>
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Public IP or Hostname</label>
                        <input type="text" id="geoTargetInput" placeholder="e.g. 8.8.8.8, 1.1.1.1, or scanme.nmap.org">
                    </div>
                    <div class="form-group" style="flex:0; min-width:auto;">
                        <label>&nbsp;</label>
                        <button class="btn" id="geoStartBtn" onclick="runGeoLookup()">🌍 Query GeoIP</button>
                    </div>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-secondary btn-sm" onclick="setGeoPreset('8.8.8.8')">Google DNS (8.8.8.8)</button>
                    <button class="btn btn-secondary btn-sm" onclick="setGeoPreset('1.1.1.1')">Cloudflare (1.1.1.1)</button>
                    <button class="btn btn-secondary btn-sm" onclick="setGeoPreset('9.9.9.9')">Quad9 (9.9.9.9)</button>
                </div>
            </div>

            <div id="geoResultCard" style="display:none;" class="control-panel">
                <div class="panel-title" id="geoCardTitle">📍 Geolocation Intel Report</div>
                <div class="grid-kpi" style="margin-bottom:0;">
                    <div class="kpi-card">
                        <div class="kpi-label">Country & City</div>
                        <div class="kpi-val" id="geoCountry" style="font-size:20px;">-</div>
                        <div style="font-size:12px; color:var(--muted);" id="geoCity">-</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">Organization / ISP</div>
                        <div class="kpi-val" id="geoIsp" style="font-size:18px;">-</div>
                        <div style="font-size:12px; color:var(--muted);" id="geoAsn">-</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">Coordinates</div>
                        <div class="kpi-val" id="geoCoords" style="font-size:18px;">-</div>
                        <div style="margin-top:6px;"><a id="geoMapLink" href="#" target="_blank" class="btn btn-secondary btn-sm">📍 Open Google Maps</a></div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">Network Type</div>
                        <div class="kpi-val" id="geoStatus" style="font-size:20px; color:var(--success);">Public WAN</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 6: DNS & AXFR -->
        <div id="tab-dns" class="tab-pane">
            <div class="control-panel">
                <div class="panel-title">🌐 DNS Enumeration & AXFR Zone Transfer Auditor</div>
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Target Domain Name</label>
                        <input type="text" id="dnsTargetInput" placeholder="e.g. google.com or scanme.nmap.org">
                    </div>
                    <div class="form-group">
                        <label>Custom Nameserver (Optional)</label>
                        <input type="text" id="dnsServerInput" placeholder="e.g. 8.8.8.8">
                    </div>
                    <div class="form-group" style="flex:0; min-width:auto;">
                        <label>&nbsp;</label>
                        <button class="btn" id="dnsStartBtn" onclick="runDnsAudit()">🌐 Run DNS Audit</button>
                    </div>
                </div>
            </div>

            <!-- AXFR Security Banner -->
            <div id="axfrBanner" style="display:none; padding:16px 20px; border-radius:10px; margin-bottom:20px; font-weight:600;"></div>

            <div class="grid-kpi" id="dnsRecordsContainer">
                <div class="kpi-card">
                    <div class="kpi-label">Authoritative Nameservers (NS)</div>
                    <div id="dnsNsList" style="font-size:13px; margin-top:8px; line-height:1.6; color:var(--text);">-</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">IPv4 Addresses (A)</div>
                    <div id="dnsAList" style="font-size:13px; margin-top:8px; line-height:1.6; color:var(--text);">-</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Mail Exchangers (MX)</div>
                    <div id="dnsMxList" style="font-size:13px; margin-top:8px; line-height:1.6; color:var(--text);">-</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Verification & SPF (TXT)</div>
                    <div id="dnsTxtList" style="font-size:12px; margin-top:8px; line-height:1.4; color:var(--muted); max-height:140px; overflow-y:auto;">-</div>
                </div>
            </div>
        </div>

        <!-- TAB 7: SECURITY REMEDIATION -->
        <div id="tab-remediation" class="tab-pane">
            <div class="control-panel">
                <div class="panel-title">🛡️ Automated Security Remediation & Host Isolation</div>
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>Offending Host IP</label>
                        <input type="text" id="remedTargetInput" placeholder="e.g. 192.168.1.150">
                    </div>
                    <div class="form-group">
                        <label>Incident Trigger / Justification</label>
                        <select id="remedReason">
                            <option value="rogue">Rogue Unauthenticated Host on LAN</option>
                            <option value="recon">Port Scanning / Reconnaissance Activity</option>
                            <option value="cve">Critical Unpatched CVE Vulnerability</option>
                            <option value="botnet">Suspicious C2 / Botnet Outbound Traffic</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex:0; min-width:auto;">
                        <label>&nbsp;</label>
                        <button class="btn btn-danger" onclick="generateRemediation()">🛡️ Generate Isolation Rules</button>
                    </div>
                </div>
            </div>

            <div id="remedResultCard" style="display:none;" class="control-panel">
                <div class="panel-title" style="color:var(--danger);">🚨 Firewall Device Isolation Commands</div>
                <div style="font-size:13px; color:var(--muted); margin-bottom:12px;">
                    Execute the following generated commands on your Linux security gateway or host to instantly drop all ingress and egress packets for the selected IP:
                </div>
                <div class="code-box">
                    <button class="copy-btn" onclick="copyCode('isolationCodeBlock')">📋 Copy</button>
                    <pre id="isolationCodeBlock"># Generating firewall rules...</pre>
                </div>
                <div style="margin-top:16px; display:flex; gap:12px; align-items:center;">
                    <button class="btn btn-danger btn-sm" onclick="executeLiveIsolation()">⚡ Apply Isolation via Kernel (Requires Root)</button>
                    <span style="font-size:12px; color:var(--muted);" id="remedStatusMsg"></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Device Tagging Modal -->
    <div class="modal-overlay" id="tagModal">
        <div class="modal-box">
            <div class="modal-header">
                <h3 style="font-size:16px;">🏷️ Edit Friendly Device Tag</h3>
                <button class="btn btn-secondary btn-sm" onclick="closeTagModal()">✕</button>
            </div>
            <div class="form-group" style="margin-bottom:12px;">
                <label>Target IP or MAC</label>
                <input type="text" id="modalTagTarget" readonly style="opacity:0.8;">
            </div>
            <div class="form-group" style="margin-bottom:12px;">
                <label>Friendly Device Label</label>
                <input type="text" id="modalTagLabel" placeholder="e.g. CEO Laptop, Living Room TV, Smart Bulb">
            </div>
            <div class="form-group" style="margin-bottom:16px;">
                <label>Audit Notes</label>
                <textarea id="modalTagNotes" rows="3" placeholder="Department, owner, or security notes..."></textarea>
            </div>
            <div style="display:flex; justify-content:space-between;">
                <button class="btn btn-danger btn-sm" onclick="deleteTag()">Delete Tag</button>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-secondary btn-sm" onclick="closeTagModal()">Cancel</button>
                    <button class="btn btn-sm" onclick="saveTag()">Save Tag</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Alerts -->
    <div id="toastContainer"></div>

    <script>
        let currentSubnet = {};
        let inventoryDevices = [];
        let deviceTags = {};

        // Theme management
        const themes = ['theme-obsidian', 'theme-cyberpunk', 'theme-light'];
        function toggleTheme() {
            let cur = document.body.className;
            let nextIdx = (themes.indexOf(cur) + 1) % themes.length;
            let nextTheme = themes[nextIdx];
            document.body.className = nextTheme;
            localStorage.setItem('cyberscan_theme', nextTheme);
            updateThemeButton(nextTheme);
        }
        function updateThemeButton(theme) {
            const btn = document.getElementById('themeBtn');
            if (theme === 'theme-cyberpunk') btn.innerText = '⚡ Cyberpunk';
            else if (theme === 'theme-light') btn.innerText = '☀️ Light';
            else btn.innerText = '🌙 Obsidian';
        }

        // Tab navigation
        function switchTab(tabId, el) {
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + tabId).classList.add('active');
            if (el) el.classList.add('active');
        }

        // Toast notifications
        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.innerHTML = `<span>${type === 'danger' ? '❌' : type === 'success' ? '✅' : 'ℹ️'}</span><span>${message}</span>`;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3500);
        }

        function copyCode(elemId) {
            const text = document.getElementById(elemId).innerText;
            navigator.clipboard.writeText(text);
            showToast('Copied to clipboard!', 'success');
        }

        // Subnet detection and initial load
        async function init() {
            const savedTheme = localStorage.getItem('cyberscan_theme') || 'theme-obsidian';
            document.body.className = savedTheme;
            updateThemeButton(savedTheme);

            try {
                const res = await fetch('/api/subnet');
                currentSubnet = await res.json();
                document.getElementById('headerTelemetry').innerText = `Interface: ${currentSubnet.interface} | Subnet: ${currentSubnet.cidr} | GW: ${currentSubnet.gateway}`;
                document.getElementById('kpiSubnet').innerText = currentSubnet.cidr || '-';
                document.getElementById('kpiInterface').innerText = currentSubnet.interface || '-';
                document.getElementById('pingTarget').value = currentSubnet.cidr || '192.168.1.0/24';
            } catch (e) {
                console.error(e);
            }

            loadInventoryData();
            loadWifiInterfaces();
        }

        // Inventory Management
        async function loadInventoryData() {
            try {
                const [invRes, tagsRes] = await Promise.all([
                    fetch('/api/inventory'),
                    fetch('/api/tags')
                ]);
                const invData = await invRes.json();
                deviceTags = await tagsRes.json();

                inventoryDevices = Object.entries(invData.devices || {}).map(([ip, info]) => ({
                    ip,
                    ...info,
                    tag: deviceTags[ip]?.label || ''
                }));

                document.getElementById('kpiTotalAssets').innerText = inventoryDevices.length;
                document.getElementById('kpiTagged').innerText = Object.keys(deviceTags).length;
                renderInventoryTable(inventoryDevices);
            } catch (e) {
                showToast('Failed to load inventory data', 'danger');
            }
        }

        function renderInventoryTable(list) {
            const tbody = document.getElementById('inventoryRows');
            if (!list.length) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--muted);">No devices tracked in inventory yet. Run a Subnet Ping Sweep!</td></tr>';
                return;
            }

            tbody.innerHTML = list.map(d => `
                <tr>
                    <td><span class="badge badge-success">● ONLINE</span></td>
                    <td><strong style="color:var(--text); cursor:pointer;" onclick="quickAuditPorts('${d.ip}')">${d.ip}</strong></td>
                    <td style="font-family:monospace; color:var(--muted);">${d.MAC || '-'}</td>
                    <td>${d.Vendor ? `<span class="badge badge-info">${d.Vendor}</span>` : '-'}</td>
                    <td>${d.tag ? `<span class="badge badge-purple">${d.tag}</span> ` : ''}${d.Hostname || d.DeviceType || '-'}</td>
                    <td>${d.TimesSeen || 1}</td>
                    <td style="color:var(--muted); font-size:12px;">${(d.LastSeen || '').slice(0, 19).replace('T', ' ')}</td>
                    <td>
                        <div style="display:flex; gap:6px;">
                            <button class="btn btn-secondary btn-sm" onclick="quickAuditPorts('${d.ip}')">🔍 Scan</button>
                            <button class="btn btn-secondary btn-sm" onclick="openTagModal('${d.ip}', '${d.tag || ''}')">🏷️ Tag</button>
                            <button class="btn btn-danger btn-sm" onclick="quickIsolate('${d.ip}')">🛡️ Isolate</button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        function filterInventoryTable() {
            const q = document.getElementById('invSearchInput').value.toLowerCase();
            const filtered = inventoryDevices.filter(d => 
                d.ip.toLowerCase().includes(q) ||
                (d.MAC && d.MAC.toLowerCase().includes(q)) ||
                (d.Vendor && d.Vendor.toLowerCase().includes(q)) ||
                (d.Hostname && d.Hostname.toLowerCase().includes(q)) ||
                (d.tag && d.tag.toLowerCase().includes(q))
            );
            renderInventoryTable(filtered);
        }

        // Tag Modal actions
        let currentModalTarget = '';
        function openTagModal(target, existingLabel = '') {
            currentModalTarget = target;
            document.getElementById('modalTagTarget').value = target;
            document.getElementById('modalTagLabel').value = existingLabel;
            document.getElementById('modalTagNotes').value = deviceTags[target]?.notes || '';
            document.getElementById('tagModal').classList.add('active');
        }
        function closeTagModal() {
            document.getElementById('tagModal').classList.remove('active');
        }
        async function saveTag() {
            const label = document.getElementById('modalTagLabel').value.trim();
            const notes = document.getElementById('modalTagNotes').value.trim();
            if (!label) {
                showToast('Please specify a label', 'danger');
                return;
            }
            try {
                await fetch('/api/tag', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: currentModalTarget, label, notes })
                });
                showToast(`Tag saved for ${currentModalTarget}`, 'success');
                closeTagModal();
                loadInventoryData();
            } catch (e) {
                showToast('Failed to save tag', 'danger');
            }
        }
        async function deleteTag() {
            try {
                await fetch('/api/tag/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: currentModalTarget })
                });
                showToast(`Tag removed for ${currentModalTarget}`, 'success');
                closeTagModal();
                loadInventoryData();
            } catch (e) {
                showToast('Failed to delete tag', 'danger');
            }
        }

        // Quick Navigation shortcuts
        function quickAuditPorts(ip) {
            document.getElementById('portTarget').value = ip;
            switchTab('ports', document.querySelectorAll('.tab-btn')[2]);
            runPortScan();
        }
        function quickIsolate(ip) {
            document.getElementById('remedTargetInput').value = ip;
            switchTab('remediation', document.querySelectorAll('.tab-btn')[6]);
            generateRemediation();
        }

        // TAB 2: Subnet Ping Sweep
        function setPingPreset(mode) {
            if (mode === 'detected') document.getElementById('pingTarget').value = currentSubnet.cidr || '192.168.1.0/24';
            else if (mode === 'gateway') document.getElementById('pingTarget').value = currentSubnet.gateway || '192.168.1.1';
            else if (mode === 'local') document.getElementById('pingTarget').value = '127.0.0.1';
        }

        async function runPingSweep() {
            const target = document.getElementById('pingTarget').value.trim();
            const threads = parseInt(document.getElementById('pingThreads').value) || 30;
            const timeout = parseFloat(document.getElementById('pingTimeout').value) || 1.0;
            if (!target) return showToast('Please specify a target subnet or IP', 'danger');

            const btn = document.getElementById('pingStartBtn');
            const summary = document.getElementById('pingSummary');
            const tbody = document.getElementById('pingResultsRows');

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Scanning Subnet...';
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--muted);"><span class="spinner"></span> Probing active IP endpoints across CIDR space...</td></tr>';

            const startTime = performance.now();
            try {
                const res = await fetch('/api/scan/ping', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, threads, timeout })
                });
                const data = await res.json();
                const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);

                const list = (data.results || []).filter(r => r.alive);
                summary.innerHTML = `<strong>Scan Completed:</strong> Discovered <strong>${list.length}</strong> active hosts in ${elapsed}s across <code>${target}</code>.`;

                if (!list.length) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--muted);">No responsive hosts found on target.</td></tr>';
                } else {
                    tbody.innerHTML = list.map(r => `
                        <tr>
                            <td><strong style="color:var(--text);">${r.target || target}</strong></td>
                            <td><span class="badge badge-success">● ALIVE</span></td>
                            <td><span class="badge ${r.rtt_avg < 10 ? 'badge-success' : r.rtt_avg < 50 ? 'badge-warning' : 'badge-danger'}">${(r.rtt_avg || 0).toFixed(2)} ms</span></td>
                            <td>${r.loss_percent || 0}%</td>
                            <td style="color:var(--muted); font-size:12px;">TTL: ${r.ttl || '-'} (${r.os_guess || 'Unknown'})</td>
                            <td>
                                <button class="btn btn-secondary btn-sm" onclick="quickAuditPorts('${r.target || target}')">🔍 Audit Ports</button>
                            </td>
                        </tr>
                    `).join('');
                }
                loadInventoryData();
                showToast(`Ping sweep complete: ${list.length} hosts found`, 'success');
            } catch (e) {
                showToast('Ping sweep failed', 'danger');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '🚀 Launch Ping Sweep';
            }
        }

        // TAB 3: Port Scanner
        function setPortPreset(preset) {
            const input = document.getElementById('portListInput');
            if (preset === 'web_remote') input.value = "21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443";
            else if (preset === 'db') input.value = "1433, 1521, 3306, 5432, 6379, 27017";
            else if (preset === 'web') input.value = "80, 443, 8000, 8080, 8443, 8888, 9000";
            else if (preset === 'windows') input.value = "135, 137, 138, 139, 445, 3389";
            else if (preset === 'udp') input.value = "53, 67, 68, 69, 123, 161, 5353";
        }

        async function runPortScan() {
            const ip = document.getElementById('portTarget').value.trim();
            const proto = document.getElementById('portProtocol').value;
            const timeout = parseFloat(document.getElementById('portTimeout').value) || 0.8;
            const portsStr = document.getElementById('portListInput').value;
            if (!ip) return showToast('Please enter a target IP', 'danger');

            const ports = portsStr.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p > 0 && p <= 65535);
            if (!ports.length) return showToast('Please provide valid port numbers', 'danger');

            const btn = document.getElementById('portStartBtn');
            const tbody = document.getElementById('portResultsRows');
            const riskCard = document.getElementById('riskGaugeCard');

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Auditing Ports...';
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--muted);"><span class="spinner"></span> Connecting to ports and fingerprinting services...</td></tr>';
            riskCard.style.display = 'none';

            try {
                const endpoint = proto === 'udp' ? '/api/scan/udp' : '/api/scan/tcp';
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, ports, timeout })
                });
                const data = await res.json();
                const openPorts = data.open_ports || data.responsive_ports || [];
                const risk = data.risk || { score: 0, level: 'CLEAN', findings: [] };

                // Render Risk Card
                riskCard.style.display = 'flex';
                document.getElementById('riskCircle').innerText = risk.score || 0;
                document.getElementById('riskCircle').style.background = risk.color || (risk.score > 70 ? 'var(--danger)' : risk.score > 30 ? 'var(--warning)' : 'var(--success)');
                document.getElementById('riskLevelTitle').innerText = `Host Security Posture: ${risk.level || 'CLEAN'}`;
                document.getElementById('riskBadge').innerText = `${risk.score || 0}/100`;
                document.getElementById('riskSummaryText').innerText = (risk.findings && risk.findings.length) 
                    ? risk.findings.join(' • ') 
                    : 'No critical risk factors or dangerous ports flagged.';

                // Render Table Rows
                if (!openPorts.length) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--muted);">No open or responsive ports discovered on tested range.</td></tr>';
                } else {
                    tbody.innerHTML = openPorts.map(p => {
                        const cves = p.cves || [];
                        const cveHtml = cves.length 
                            ? cves.map(c => `<div style="margin-bottom:4px;"><span class="badge badge-danger">${c.cve}</span> <strong style="font-size:11px;">${c.title}</strong></div>`).join('')
                            : '<span style="color:var(--muted); font-size:11px;">None detected in local DB</span>';

                        return `
                            <tr>
                                <td><strong style="color:var(--text);">${p.port}</strong></td>
                                <td><span class="badge badge-info">${p.protocol || 'TCP'}</span></td>
                                <td><strong>${p.service || 'Unknown'}</strong></td>
                                <td><span class="badge badge-success">● OPEN</span></td>
                                <td style="font-size:12px; color:var(--muted);">${p.latency_ms ? p.latency_ms + ' ms' : '-'}</td>
                                <td style="font-family:monospace; font-size:11px; color:var(--muted); max-width:240px; word-break:break-all;">${p.banner && p.banner !== '-' ? p.banner : p.version || '-'}</td>
                                <td>${cveHtml}</td>
                            </tr>
                        `;
                    }).join('');
                }
                showToast(`Port scan complete: ${openPorts.length} open ports`, 'success');
            } catch (e) {
                showToast('Port audit failed', 'danger');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '🔎 Execute Port Audit';
            }
        }

        // TAB 4: Wi-Fi Recon
        async function loadWifiInterfaces() {
            try {
                const res = await fetch('/api/wifi/interfaces');
                const data = await res.json();
                const sel = document.getElementById('wifiInterfaceSelect');
                (data.interfaces || []).forEach(iface => {
                    const opt = document.createElement('option');
                    opt.value = iface;
                    opt.innerText = iface;
                    sel.appendChild(opt);
                });
            } catch (e) {}
        }

        async function runWifiScan() {
            const iface = document.getElementById('wifiInterfaceSelect').value;
            const btn = document.getElementById('wifiStartBtn');
            const tbody = document.getElementById('wifiResultsRows');

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Scanning Airspace...';
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--muted);"><span class="spinner"></span> Listening for 802.11 beacon frames...</td></tr>';

            try {
                const res = await fetch('/api/scan/wifi?interface=' + encodeURIComponent(iface));
                const data = await res.json();
                const nets = data.networks || [];

                if (!nets.length) {
                    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--muted);">${data.message || 'No wireless networks detected or interface busy.'}</td></tr>`;
                } else {
                    tbody.innerHTML = nets.map(n => {
                        const sig = parseInt(n.signal) || 0;
                        const sigColor = sig >= 75 ? 'var(--success)' : sig >= 45 ? 'var(--warning)' : 'var(--danger)';
                        const isInsecure = n.insecure || (n.security && (n.security.includes('OPEN') || n.security.includes('WEP')));

                        return `
                            <tr>
                                <td><strong style="color:var(--text);">${n.ssid || '<Hidden SSID>'}</strong></td>
                                <td style="font-family:monospace; color:var(--muted);">${n.bssid || '-'}</td>
                                <td>
                                    <div class="sig-meter">
                                        <div class="sig-bar-box">
                                            <div class="sig-fill" style="width:${sig}%; background:${sigColor};"></div>
                                        </div>
                                        <span>${sig}%</span>
                                    </div>
                                </td>
                                <td>CH ${n.channel || '?'}</td>
                                <td><span class="badge ${isInsecure ? 'badge-danger' : 'badge-info'}">${n.security || 'WPA2'}</span></td>
                                <td>
                                    ${isInsecure 
                                        ? '<span class="badge badge-danger">⚠️ INSECURE OPEN AP</span>' 
                                        : '<span class="badge badge-success">● SECURED</span>'}
                                </td>
                            </tr>
                        `;
                    }).join('');
                }
                showToast(`Wi-Fi scan finished: ${nets.length} APs found`, 'success');
            } catch (e) {
                showToast('Wi-Fi scan failed', 'danger');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '📡 Discover Nearby Wi-Fi';
            }
        }

        // TAB 5: GeoIP Lookup
        function setGeoPreset(ip) {
            document.getElementById('geoTargetInput').value = ip;
            runGeoLookup();
        }

        async function runGeoLookup() {
            const ip = document.getElementById('geoTargetInput').value.trim();
            if (!ip) return showToast('Please enter an IP or domain', 'danger');

            const btn = document.getElementById('geoStartBtn');
            const card = document.getElementById('geoResultCard');

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Querying Intel...';

            try {
                const res = await fetch('/api/scan/geo?ip=' + encodeURIComponent(ip));
                const data = await res.json();

                card.style.display = 'block';
                if (data.status === 'private') {
                    document.getElementById('geoCountry').innerText = 'Local / RFC1918';
                    document.getElementById('geoCity').innerText = 'Internal LAN Network';
                    document.getElementById('geoIsp').innerText = 'Private Gateway';
                    document.getElementById('geoAsn').innerText = 'Non-Routable on WAN';
                    document.getElementById('geoCoords').innerText = 'N/A';
                    document.getElementById('geoStatus').innerText = 'Private LAN';
                    document.getElementById('geoStatus').style.color = 'var(--muted)';
                    document.getElementById('geoMapLink').style.display = 'none';
                } else {
                    document.getElementById('geoCountry').innerText = `${data.country || 'Unknown'} (${data.countryCode || ''})`;
                    document.getElementById('geoCity').innerText = `${data.city || '-'}, ${data.regionName || ''}`;
                    document.getElementById('geoIsp').innerText = data.isp || data.org || 'Unknown ISP';
                    document.getElementById('geoAsn').innerText = data.as || '-';
                    document.getElementById('geoCoords').innerText = `${data.lat || 0}, ${data.lon || 0}`;
                    document.getElementById('geoStatus').innerText = 'Public WAN';
                    document.getElementById('geoStatus').style.color = 'var(--success)';
                    document.getElementById('geoMapLink').style.display = 'inline-flex';
                    document.getElementById('geoMapLink').href = `https://www.google.com/maps?q=${data.lat},${data.lon}`;
                }
                showToast(`Intel retrieved for ${ip}`, 'success');
            } catch (e) {
                showToast('GeoIP query failed', 'danger');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '🌍 Query GeoIP';
            }
        }

        // TAB 6: DNS & AXFR
        async function runDnsAudit() {
            const target = document.getElementById('dnsTargetInput').value.trim();
            const server = document.getElementById('dnsServerInput').value.trim();
            if (!target) return showToast('Please specify a target domain', 'danger');

            const btn = document.getElementById('dnsStartBtn');
            const banner = document.getElementById('axfrBanner');

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Resolving DNS...';

            try {
                const res = await fetch(`/api/scan/dns?target=${encodeURIComponent(target)}&server=${encodeURIComponent(server)}`);
                const data = await res.json();

                // AXFR banner
                banner.style.display = 'block';
                if (data.axfr_vulnerable) {
                    banner.style.background = 'rgba(239, 68, 68, 0.2)';
                    banner.style.border = '1px solid var(--danger)';
                    banner.style.color = '#f87171';
                    banner.innerHTML = '🚨 <strong>CRITICAL MISCONFIGURATION:</strong> Authoritative nameserver permits unrestricted AXFR Zone Transfers! Internal zone data leaked.';
                } else {
                    banner.style.background = 'rgba(16, 185, 129, 0.15)';
                    banner.style.border = '1px solid var(--success)';
                    banner.style.color = '#34d399';
                    banner.innerHTML = '✅ <strong>AXFR Zone Transfer Protected:</strong> Authoritative nameservers securely rejected unauthenticated zone transfers.';
                }

                // Render Records
                const recs = data.records || {};
                document.getElementById('dnsNsList').innerHTML = (data.nameservers || []).map(ns => `<div>• <code>${ns}</code></div>`).join('') || 'None found';
                document.getElementById('dnsAList').innerHTML = (recs.A || []).map(a => `<div>• <code>${a}</code></div>`).join('') || 'None found';
                document.getElementById('dnsMxList').innerHTML = (recs.MX || []).map(mx => `<div>• <code>${mx}</code></div>`).join('') || 'None found';
                document.getElementById('dnsTxtList').innerHTML = (recs.TXT || []).map(txt => `<div>• ${txt}</div>`).join('') || 'None found';

                showToast(`DNS audit completed for ${target}`, 'success');
            } catch (e) {
                showToast('DNS audit failed', 'danger');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '🌐 Run DNS Audit';
            }
        }

        // TAB 7: Remediation
        async function generateRemediation() {
            const ip = document.getElementById('remedTargetInput').value.trim();
            if (!ip) return showToast('Please specify an offending host IP', 'danger');

            try {
                const res = await fetch(`/api/remediation/rules?ip=${encodeURIComponent(ip)}`);
                const data = await res.json();
                const rules = data.rules || [
                    `iptables -I INPUT 1 -s ${ip} -j DROP`,
                    `iptables -I FORWARD 1 -s ${ip} -j DROP`,
                    `iptables -I OUTPUT 1 -d ${ip} -j DROP`
                ];

                document.getElementById('isolationCodeBlock').innerText = 
                    `# Immediate Host Firewall Isolation Script for ${ip}\\n` +
                    `# Generated by NetPulse Studio\\n\\n` +
                    rules.map(r => `sudo ${r}`).join('\\n') + 
                    `\\n\\n# Verification command:\\nsudo iptables -L -n -v | grep ${ip}`;

                document.getElementById('remedResultCard').style.display = 'block';
                document.getElementById('remedStatusMsg').innerText = '';
                showToast(`Isolation rules generated for ${ip}`, 'success');
            } catch (e) {
                showToast('Failed to generate isolation rules', 'danger');
            }
        }

        async function executeLiveIsolation() {
            const ip = document.getElementById('remedTargetInput').value.trim();
            if (!ip) return showToast('Please specify target IP', 'danger');

            try {
                const res = await fetch('/api/remediation/isolate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, execute: true })
                });
                const data = await res.json();
                document.getElementById('remedStatusMsg').innerText = data.message || 'Action executed';
                showToast(data.message || 'Execution processed', data.executed ? 'success' : 'warning');
            } catch (e) {
                showToast('Execution error', 'danger');
            }
        }

        window.onload = init;
    </script>
</body>
</html>
"""


class ScannerAPIRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler providing full-featured Web GUI and REST endpoints."""

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
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

    def _send_download(self, content_str, filename, content_type="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(content_str.encode("utf-8"))

    def do_OPTIONS(self):
        self._send_json({"status": "ok"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        if path in ("", "/dashboard"):
            self._send_html(WEB_DASHBOARD_HTML)

        elif path in ("/api/inventory", "/api/hosts"):
            history = ScanHistoryManager.load_history()
            self._send_json(history)

        elif path == "/api/tags":
            tags = DeviceTagManager.load_tags()
            self._send_json(tags)

        elif path == "/api/subnet":
            subnet_info = get_local_subnet()
            self._send_json(subnet_info)

        elif path == "/api/wifi/interfaces":
            ifaces = get_wireless_interfaces()
            self._send_json({"interfaces": ifaces})

        elif path == "/api/scan/wifi":
            iface = query.get("interface", [""])[0] or None
            results = scan_wifi(interface=iface)
            self._send_json(results)

        elif path == "/api/scan/geo":
            ip = query.get("ip", [""])[0]
            if not ip:
                self._send_json({"status": "error", "message": "Missing 'ip' query parameter"}, status=400)
                return
            geo = get_ip_geolocation(ip)
            self._send_json(geo)

        elif path == "/api/scan/dns":
            target = query.get("target", [""])[0]
            server = query.get("server", [""])[0] or None
            if not target:
                self._send_json({"error": "Missing 'target' query parameter"}, status=400)
                return
            results = enumerate_domain_dns(target, custom_server=server)
            self._send_json(results)

        elif path == "/api/remediation/rules":
            ip = query.get("ip", [""])[0]
            rules = generate_isolation_rules(ip) if ip else []
            self._send_json({"ip": ip, "rules": rules})

        elif path == "/api/export":
            export_fmt = query.get("format", ["json"])[0].lower()
            history = ScanHistoryManager.load_history()
            tags = DeviceTagManager.load_tags()

            if export_fmt == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["IP", "MAC", "Vendor", "Hostname", "Tag", "TimesSeen", "LastSeen"])
                for ip, info in history.get("devices", {}).items():
                    tag = tags.get(ip, {}).get("label", "")
                    writer.writerow([
                        ip,
                        info.get("MAC", ""),
                        info.get("Vendor", ""),
                        info.get("Hostname") or info.get("DeviceType", ""),
                        tag,
                        info.get("TimesSeen", 1),
                        info.get("LastSeen", "")
                    ])
                self._send_download(output.getvalue(), "network_inventory.csv", "text/csv")
            else:
                self._send_download(json.dumps(history, indent=2), "network_inventory.json", "application/json")

        elif path == "/api/help":
            self._send_json({
                "endpoints": {
                    "GET /": "Full Interactive NetPulse Studio Web GUI",
                    "GET /api/inventory": "Discovered host assets and lifecycle history",
                    "GET /api/tags": "Configured friendly device labels and notes",
                    "GET /api/subnet": "Auto-detected local CIDR subnet and gateway",
                    "GET /api/wifi/interfaces": "Available wireless network interfaces",
                    "GET /api/scan/wifi?interface=...": "Scan nearby 802.11 Wi-Fi networks",
                    "GET /api/scan/geo?ip=...": "Retrieve WAN IP geolocation & ASN intelligence",
                    "GET /api/scan/dns?target=...": "Query DNS records and test AXFR zone transfer",
                    "GET /api/export?format=csv|json": "Download inventory file",
                    "POST /api/scan/ping": "Execute ping sweep or single probe",
                    "POST /api/scan/tcp": "Audit open TCP ports, banners, and offline CVEs",
                    "POST /api/scan/udp": "Probe responsive UDP service ports",
                    "POST /api/tag": "Save friendly device tag and notes",
                    "POST /api/tag/delete": "Remove friendly tag",
                    "POST /api/remediation/isolate": "Generate or execute host firewall isolation"
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
            threads = int(params.get("threads", 30))
            timeout = float(params.get("timeout", 1.0))
            if "/" in target:
                results = ping_sweep(target, max_workers=threads, timeout=timeout)
            else:
                p_res = execute_ping(target, count=params.get("count", 2), timeout=timeout)
                p_res["target"] = target
                results = [p_res]
            self._send_json({"target": target, "results": results})

        elif path == "/api/scan/tcp":
            ip = params.get("ip")
            if not ip:
                self._send_json({"error": "Missing 'ip' parameter"}, status=400)
                return
            ports = params.get("ports", [21, 22, 80, 443, 3306, 8080])
            timeout = float(params.get("timeout", 0.8))
            results = tcp_connect_scan(ip, ports, timeout=timeout)
            
            # Enrich open ports with CVEs
            for p in results:
                p["cves"] = lookup_cves(p.get("service", ""), p.get("version") or p.get("banner", ""))
            
            risk = calculate_host_risk(results)
            self._send_json({"ip": ip, "open_ports": results, "risk": risk})

        elif path == "/api/scan/udp":
            ip = params.get("ip")
            if not ip:
                self._send_json({"error": "Missing 'ip' parameter"}, status=400)
                return
            ports = params.get("ports", [53, 123, 161, 5353])
            timeout = float(params.get("timeout", 1.5))
            results = udp_scan(ip, ports, timeout=timeout)
            self._send_json({"ip": ip, "responsive_ports": results})

        elif path == "/api/scan/wifi":
            iface = params.get("interface") or None
            results = scan_wifi(interface=iface)
            self._send_json(results)

        elif path == "/api/scan/geo":
            ip = params.get("ip", "")
            geo = get_ip_geolocation(ip) if ip else {"status": "error", "message": "Missing 'ip'"}
            self._send_json(geo)

        elif path == "/api/scan/dns":
            target = params.get("target", "")
            server = params.get("server") or None
            results = enumerate_domain_dns(target, custom_server=server) if target else {"error": "Missing 'target'"}
            self._send_json(results)

        elif path == "/api/tag":
            target = params.get("target")
            label = params.get("label")
            notes = params.get("notes", "")
            if not target or not label:
                self._send_json({"error": "Missing 'target' or 'label'"}, status=400)
                return
            DeviceTagManager.set_tag(target, label, notes)
            self._send_json({"status": "saved", "target": target, "label": label})

        elif path == "/api/tag/delete":
            target = params.get("target")
            if not target:
                self._send_json({"error": "Missing 'target'"}, status=400)
                return
            DeviceTagManager.delete_tag(target)
            self._send_json({"status": "deleted", "target": target})

        elif path == "/api/remediation/isolate":
            ip = params.get("ip")
            if not ip:
                self._send_json({"error": "Missing 'ip'"}, status=400)
                return
            execute = bool(params.get("execute", False))
            rules = generate_isolation_rules(ip)
            executed = False
            msg = "Rules generated."
            if execute:
                executed, msg = isolate_device(ip)
            self._send_json({"ip": ip, "rules": rules, "executed": executed, "message": msg})

        else:
            self._send_json({"error": "Unknown POST endpoint"}, status=404)


def start_server(host="127.0.0.1", port=8080):
    """Starts the embedded HTTP web server and API daemon."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, ScannerAPIRequestHandler)
    print("\n" + "=" * 75)
    print(f"[*] NetPulse Studio Web GUI & REST API Daemon Active!")
    print(f"[*] Web App GUI:    http://{host}:{port}/")
    print(f"[*] Asset History:  http://{host}:{port}/api/inventory")
    print(f"[*] REST Help:      http://{host}:{port}/api/help")
    print(f"[*] Press Ctrl+C to terminate server.")
    print("=" * 75 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")
        httpd.server_close()
