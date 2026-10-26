"""
Interactive Standalone HTML Executive Dashboard Generator.
100% Offline-Ready (Zero CDN dependencies).
Features live client-side search, status & risk filtering, sorting,
CVE vulnerability findings, network topology mapping, collapsible device inspection drawers,
and dynamic Theme Switcher (Dark Obsidian, Executive Light, Cyberpunk Matrix).
"""

import html
from datetime import datetime

from network_scanner import __version__


THEME_CONFIGS = {
    "dark": {
        "name": "Dark Obsidian",
        "bg_body": "#0b0f19",
        "bg_card": "#151d2f",
        "bg_card_hover": "#1c263c",
        "border_color": "#243048",
        "text_main": "#f1f5f9",
        "text_muted": "#94a3b8",
        "header_bg": "#111827",
        "primary": "#0ea5e9",
        "primary_glow": "rgba(14, 165, 233, 0.2)",
    },
    "light": {
        "name": "Executive Light",
        "bg_body": "#f8fafc",
        "bg_card": "#ffffff",
        "bg_card_hover": "#f1f5f9",
        "border_color": "#cbd5e1",
        "text_main": "#0f172a",
        "text_muted": "#64748b",
        "header_bg": "#e2e8f0",
        "primary": "#2563eb",
        "primary_glow": "rgba(37, 99, 235, 0.15)",
    },
    "cyberpunk": {
        "name": "Cyberpunk Neon",
        "bg_body": "#050508",
        "bg_card": "#0d1117",
        "bg_card_hover": "#161b22",
        "border_color": "#00ff6633",
        "text_main": "#00ff66",
        "text_muted": "#00cc55aa",
        "header_bg": "#022110",
        "primary": "#00ffcc",
        "primary_glow": "rgba(0, 255, 204, 0.25)",
    }
}


def generate_html_report(title, scan_type, target, stats, items, output_path="report.html", 
                         risk_data=None, cve_data=None, topology_svg="", theme="dark"):
    """
    Generates a modern, standalone, interactive HTML report with theme support.
    
    Args:
        title (str): Report title
        scan_type (str): Scan category (ARP, TCP, UDP, etc.)
        target (str): Target subnet or host
        stats (dict): High level summary counts
        items (list): Discovered host or port dictionaries
        output_path (str): Destination path for HTML file
        risk_data (dict, optional): Risk score and remediation advice
        cve_data (dict, optional): Identified CVEs
        topology_svg (str, optional): SVG diagram markup
        theme (str): Initial active theme ('dark', 'light', 'cyberpunk')
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_theme = theme.lower() if theme and theme.lower() in THEME_CONFIGS else "dark"

    # Build metric cards HTML
    cards_html = ""
    for label, val in stats.items():
        cards_html += f"""
        <div class="card">
            <div class="card-label">{html.escape(label)}</div>
            <div class="card-value">{html.escape(str(val))}</div>
        </div>
        """

    # If risk data provided, add risk posture card
    if risk_data:
        score = risk_data.get("score", 0)
        level = risk_data.get("level", "CLEAN")
        color = risk_data.get("color", "#10b981")
        cards_html += f"""
        <div class="card" style="border-left: 4px solid {color};">
            <div class="card-label">Security Posture</div>
            <div class="card-value" style="color: {color};">{score}/100 <span class="badge" style="background: {color}22; color: {color}; border: 1px solid {color}55;">{level}</span></div>
        </div>
        """

    # Build table headers & rows
    table_headers_html = ""
    table_rows_html = ""

    if items:
        keys = list(items[0].keys())
        display_keys = [k for k in keys if k not in ("ProfileDetails", "Notes", "raw_banner")][:7]
        table_headers_html = "".join(f"<th onclick=\"sortTable('{k}')\" style=\"cursor:pointer\">{html.escape(k)} ⬍</th>" for k in display_keys)

        for idx, item in enumerate(items):
            row_cells = ""
            row_status = str(item.get("Status", "")).upper()
            has_warning = bool(item.get("warning") or item.get("Warning") or "WARNING" in str(item))
            row_class = "table-row"

            for k in display_keys:
                val = str(item.get(k, "-") or "-")
                badge_class = ""
                val_upper = val.upper()

                if "ONLINE" in val_upper or "ALIVE" in val_upper or "OPEN" in val_upper:
                    badge_class = "badge badge-online"
                elif "NEW" in val_upper:
                    badge_class = "badge badge-new"
                elif "OFFLINE" in val_upper:
                    badge_class = "badge badge-offline"
                elif "ROUTER" in val_upper or "GATEWAY" in val_upper:
                    badge_class = "badge badge-role"
                elif "WARNING" in k.lower() and val != "-":
                    badge_class = "badge badge-warning"
                elif k.lower() == "devicetype":
                    badge_class = "badge badge-role"

                if badge_class:
                    content = f'<span class="{badge_class}">{html.escape(val)}</span>'
                else:
                    content = html.escape(val)

                row_cells += f"<td>{content}</td>"

            # Extended drawer content
            drawer_items = [f"<strong>{html.escape(k)}:</strong> {html.escape(str(v))}" for k, v in item.items() if str(v) and str(v) != "-"]
            drawer_html = f"""
            <tr class="drawer-row" id="drawer-{idx}" style="display:none;">
                <td colspan="{len(display_keys)}" class="drawer-cell">
                    <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px; font-weight: 600; text-transform: uppercase;">Extended Device Inspection</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 16px; font-size: 13px;">
                        {' &bull; '.join(drawer_items)}
                    </div>
                </td>
            </tr>
            """

            table_rows_html += f"""
            <tr class="{row_class}" onclick="toggleDrawer({idx})" style="cursor:pointer;" data-status="{row_status}" data-warning="{str(has_warning).lower()}">
                {row_cells}
            </tr>
            {drawer_html}
            """
    else:
        table_headers_html = "<th>Status</th>"
        table_rows_html = "<tr><td>No records found.</td></tr>"

    # Remediation alert box
    remediation_box_html = ""
    if risk_data and risk_data.get("recommendations"):
        recs = "".join(f"<li>{html.escape(r)}</li>" for r in risk_data["recommendations"])
        remediation_box_html = f"""
        <div class="remediation-box">
            <h3>⚠ Prioritized Security Remediations</h3>
            <ul>{recs}</ul>
        </div>
        """

    # CVE Vulnerability findings box
    cve_box_html = ""
    if cve_data and cve_data.get("cves"):
        cve_items = ""
        for c in cve_data["cves"]:
            sev_color = "#ef4444" if c.get("severity") == "CRITICAL" else "#f97316"
            cve_items += f"""
            <div class="cve-item" style="border-left:4px solid {sev_color}; padding:14px; border-radius:8px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <strong style="font-size:14px;">{html.escape(c['title'])}</strong>
                    <span class="badge" style="background:{sev_color}22; color:{sev_color}; border:1px solid {sev_color}55;">{c.get('cve', '')} &bull; CVSS {c.get('cvss', 'N/A')}</span>
                </div>
                <p style="color:var(--text-muted); font-size:12px; margin-bottom:6px;">{html.escape(c.get('summary', ''))}</p>
                <div style="font-size:12px; color:var(--primary);"><strong>Remediation:</strong> {html.escape(c.get('remediation', ''))}</div>
            </div>
            """
        cve_box_html = f"""
        <div class="cve-box" style="margin-bottom: 24px;">
            <h3 style="color:#f87171; font-size:16px; margin-bottom:12px; display:flex; align-items:center; gap:8px;">
                🛡 Identified CVE Vulnerabilities ({len(cve_data['cves'])})
            </h3>
            {cve_items}
        </div>
        """

    # Topology section
    topology_section_html = ""
    if topology_svg:
        topology_section_html = f"""
        <div style="margin-bottom: 28px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 style="font-size:16px;">🌐 Visual Network Topology Map</h3>
                <span style="font-size:12px; color:var(--text-muted);">Hierarchical subnet layout</span>
            </div>
            <div style="overflow-x:auto;" class="topology-wrapper">
                {topology_svg}
            </div>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="{active_theme}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)} - {html.escape(target)}</title>
    <style>
        /* Theme Variables */
        :root[data-theme="dark"] {{
            --bg-body: #0b0f19;
            --bg-card: #151d2f;
            --bg-card-hover: #1c263c;
            --border-color: #243048;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --header-bg: #111827;
            --primary: #0ea5e9;
            --primary-glow: rgba(14, 165, 233, 0.2);
            --drawer-bg: #111827;
        }}
        :root[data-theme="light"] {{
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-card-hover: #f1f5f9;
            --border-color: #cbd5e1;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --header-bg: #f1f5f9;
            --primary: #2563eb;
            --primary-glow: rgba(37, 99, 235, 0.15);
            --drawer-bg: #f8fafc;
        }}
        :root[data-theme="cyberpunk"] {{
            --bg-body: #050508;
            --bg-card: #0d1117;
            --bg-card-hover: #161b22;
            --border-color: #00ff6644;
            --text-main: #00ff66;
            --text-muted: #00cc55aa;
            --header-bg: #031a0e;
            --primary: #00ffcc;
            --primary-glow: rgba(0, 255, 204, 0.25);
            --drawer-bg: #06110a;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 32px 20px;
            line-height: 1.5;
            transition: background-color 0.2s ease, color 0.2s ease;
        }}
        .container {{
            max-width: 1260px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 24px;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-title h1 {{
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .badge-type {{
            background: var(--primary-glow);
            color: var(--primary);
            border: 1px solid var(--primary);
            padding: 2px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .header-right {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 8px;
        }}
        .header-meta {{
            color: var(--text-muted);
            font-size: 13px;
            text-align: right;
        }}
        .theme-select {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            cursor: pointer;
            outline: none;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            transition: transform 0.15s ease, background 0.15s ease;
        }}
        .card:hover {{
            background: var(--bg-card-hover);
        }}
        .card-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .card-value {{
            font-size: 24px;
            font-weight: 700;
        }}
        .remediation-box {{
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .remediation-box h3 {{
            color: #f87171;
            font-size: 15px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .remediation-box ul {{
            margin-left: 20px;
            font-size: 13px;
        }}
        .remediation-box li {{
            margin-bottom: 6px;
        }}
        .cve-item {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
        }}
        .controls-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            max-width: 450px;
        }}
        .search-box input {{
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 10px 16px;
            color: var(--text-main);
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-box input:focus {{
            border-color: var(--primary);
        }}
        .filter-buttons {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .filter-btn.active, .filter-btn:hover {{
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
        }}
        .table-container {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow-x: auto;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: var(--header-bg);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 11px;
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-color);
            user-select: none;
        }}
        th:hover {{
            color: var(--text-main);
        }}
        td {{
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}
        tr.table-row:hover td {{
            background: rgba(125, 125, 125, 0.05);
        }}
        .drawer-cell {{
            background: var(--drawer-bg);
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-color);
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }}
        .badge-online {{ background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-new {{ background: rgba(14, 165, 233, 0.15); color: #0ea5e9; border: 1px solid rgba(14, 165, 233, 0.3); }}
        .badge-offline {{ background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }}
        .badge-role {{ background: rgba(168, 85, 247, 0.15); color: #a855f7; border: 1px solid rgba(168, 85, 247, 0.3); }}
        .badge-warning {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            color: var(--text-muted);
            font-size: 12px;
        }}

        @media print {{
            body {{
                background: #ffffff !important;
                color: #000000 !important;
                padding: 0;
            }}
            .theme-select, .controls-bar, .filter-buttons {{
                display: none !important;
            }}
            .card, .table-container {{
                border: 1px solid #ccc !important;
                box-shadow: none !important;
            }}
            th {{
                background: #eee !important;
                color: #000 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>{html.escape(title)} <span class="badge-type">{html.escape(scan_type)}</span></h1>
                <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Target: <strong>{html.escape(target)}</strong> &bull; Click any row for details</p>
            </div>
            <div class="header-right">
                <div class="header-meta">
                    <div>Generated: <strong>{timestamp}</strong></div>
                    <div>Engine: <strong>Network Scanner Suite v{__version__}</strong></div>
                </div>
                <select id="themeSelector" class="theme-select" onchange="changeTheme(this.value)">
                    <option value="dark" {'selected' if active_theme == 'dark' else ''}>🌙 Dark Obsidian</option>
                    <option value="light" {'selected' if active_theme == 'light' else ''}>☀️ Executive Light</option>
                    <option value="cyberpunk" {'selected' if active_theme == 'cyberpunk' else ''}>⚡ Cyberpunk Neon</option>
                </select>
            </div>
        </div>

        <div class="stats-grid">
            {cards_html}
        </div>

        {cve_box_html}
        {remediation_box_html}
        {topology_section_html}

        <div class="controls-bar">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search IP, MAC, hostname, role, port..." onkeyup="filterRows()">
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="setFilter('ALL', this)">All Hosts</button>
                <button class="filter-btn" onclick="setFilter('ONLINE', this)">Online</button>
                <button class="filter-btn" onclick="setFilter('NEW', this)">New</button>
                <button class="filter-btn" onclick="setFilter('OFFLINE', this)">Offline</button>
                <button class="filter-btn" onclick="setFilter('WARNING', this)">Risks / Warnings</button>
            </div>
        </div>

        <div class="table-container">
            <table id="dataTable">
                <thead>
                    <tr>{table_headers_html}</tr>
                </thead>
                <tbody>
                    {table_rows_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Network Scanner Suite &bull; Automated Security Auditing & Asset Inventory
        </div>
    </div>

    <script>
        let currentFilter = 'ALL';

        function changeTheme(themeName) {{
            document.documentElement.setAttribute('data-theme', themeName);
            try {{
                localStorage.setItem('network_scanner_theme', themeName);
            }} catch(e) {{}}
        }}

        // Restore saved theme preference if available
        try {{
            const savedTheme = localStorage.getItem('network_scanner_theme');
            if (savedTheme) {{
                document.documentElement.setAttribute('data-theme', savedTheme);
                const sel = document.getElementById('themeSelector');
                if (sel) sel.value = savedTheme;
            }}
        }} catch(e) {{}}

        function toggleDrawer(idx) {{
            const drawer = document.getElementById('drawer-' + idx);
            if (drawer) {{
                drawer.style.display = drawer.style.display === 'none' ? 'table-row' : 'none';
            }}
        }}

        function setFilter(filterType, btn) {{
            currentFilter = filterType;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterRows();
        }}

        function filterRows() {{
            const q = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('tr.table-row');

            rows.forEach((row, idx) => {{
                const status = (row.getAttribute('data-status') || '').toUpperCase();
                const hasWarning = row.getAttribute('data-warning') === 'true';
                const text = row.innerText.toLowerCase();

                let matchesFilter = true;
                if (currentFilter === 'ONLINE') matchesFilter = status.includes('ONLINE') || status.includes('ALIVE') || status.includes('OPEN');
                else if (currentFilter === 'NEW') matchesFilter = status.includes('NEW');
                else if (currentFilter === 'OFFLINE') matchesFilter = status.includes('OFFLINE');
                else if (currentFilter === 'WARNING') matchesFilter = hasWarning;

                const matchesQuery = !q || text.includes(q);
                const visible = matchesFilter && matchesQuery;
                row.style.display = visible ? '' : 'none';

                const drawer = document.getElementById('drawer-' + idx);
                if (drawer && !visible) drawer.style.display = 'none';
            }});
        }}

        let sortDirection = {{}};
        function sortTable(columnName) {{
            const table = document.getElementById('dataTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr.table-row'));
            const ths = Array.from(table.querySelectorAll('th'));
            const colIdx = ths.findIndex(th => th.innerText.includes(columnName));
            if (colIdx === -1) return;

            sortDirection[columnName] = !sortDirection[columnName];
            const asc = sortDirection[columnName];

            rows.sort((a, b) => {{
                const valA = a.children[colIdx].innerText.trim();
                const valB = b.children[colIdx].innerText.trim();
                const numA = parseFloat(valA);
                const numB = parseFloat(valB);
                if (!isNaN(numA) && !isNaN(numB)) {{
                    return asc ? numA - numB : numB - numA;
                }}
                return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
            }});

            rows.forEach(r => {{
                tbody.appendChild(r);
                const match = r.getAttribute('onclick').match(/\\d+/);
                if (match) {{
                    const drawer = document.getElementById('drawer-' + match[0]);
                    if (drawer) tbody.appendChild(drawer);
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Saved Interactive HTML report ({active_theme} theme) to: {output_path}")
