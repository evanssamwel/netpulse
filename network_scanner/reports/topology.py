"""
Network Topology Map Visualizer.
Generates clean, scalable SVG and HTML visual topology maps of discovered assets.
"""

import html


def generate_topology_svg(devices, gateway_ip=None, subnet="192.168.1.0/24"):
    """
    Renders an SVG network topology diagram representing the network hierarchy.

    Returns:
        str: Scalable Vector Graphics (SVG) code.
    """
    if not devices:
        return "<svg width='100%' height='200'><text x='20' y='40' fill='#94a3b8'>No devices discovered to map.</text></svg>"

    # Find or infer gateway
    gw_device = None
    other_devices = []

    for d in devices:
        if (gateway_ip and d.get("IP") == gateway_ip) or "Router" in d.get("DeviceType", "") or d.get("IP", "").endswith(".1"):
            if not gw_device:
                gw_device = d
                continue
        other_devices.append(d)

    if not gw_device and devices:
        gw_device = devices[0]
        other_devices = devices[1:]

    # Layout geometry
    box_w = 170
    box_h = 75
    spacing_x = 200
    num_devices = max(1, len(other_devices))
    total_w = max(900, (num_devices * spacing_x) + 100)
    gw_x = total_w // 2 - (box_w // 2)
    gw_y = 120

    nodes_svg = ""
    lines_svg = ""

    # Internet Cloud (Top Node)
    cloud_x = total_w // 2
    cloud_y = 40
    nodes_svg += f"""
    <g transform="translate({cloud_x - 50}, {cloud_y - 25})">
        <rect width="100" height="35" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="2"/>
        <text x="50" y="22" fill="#38bdf8" font-size="12" font-family="sans-serif" font-weight="bold" text-anchor="middle">🌐 INTERNET</text>
    </g>
    """
    # Connection line from Internet to Gateway
    lines_svg += f"<line x1='{cloud_x}' y1='{cloud_y + 10}' x2='{cloud_x}' y2='{gw_y}' stroke='#38bdf8' stroke-width='2' stroke-dasharray='4'/>"

    # Gateway / Router Node
    gw_name = gw_device.get("Label") or gw_device.get("Hostname") or gw_device.get("Vendor") or "Gateway"
    gw_ip = gw_device.get("IP", "Gateway")
    nodes_svg += f"""
    <g transform="translate({gw_x}, {gw_y})">
        <rect width="{box_w}" height="{box_h}" rx="10" fill="#0f172a" stroke="#0ea5e9" stroke-width="2"/>
        <text x="15" y="24" fill="#0ea5e9" font-size="11" font-weight="bold" font-family="sans-serif">ROUTER / GATEWAY</text>
        <text x="15" y="44" fill="#ffffff" font-size="12" font-weight="bold" font-family="sans-serif">{html.escape(str(gw_name)[:18])}</text>
        <text x="15" y="62" fill="#94a3b8" font-size="11" font-family="monospace">{html.escape(gw_ip)}</text>
    </g>
    """

    # Horizontal Subnet Bus Line
    bus_y = gw_y + box_h + 50
    lines_svg += f"<line x1='{gw_x + box_w // 2}' y1='{gw_y + box_h}' x2='{gw_x + box_w // 2}' y2='{bus_y}' stroke='#64748b' stroke-width='2'/>"

    if other_devices:
        first_x = 60 + (box_w // 2)
        last_x = total_w - 60 - (box_w // 2)
        lines_svg += f"<line x1='{first_x}' y1='{bus_y}' x2='{last_x}' y2='{bus_y}' stroke='#64748b' stroke-width='2'/>"

        # Children nodes
        for idx, dev in enumerate(other_devices):
            cx = 60 + (idx * spacing_x)
            cy = bus_y + 40

            # Drop line from bus
            lines_svg += f"<line x1='{cx + box_w // 2}' y1='{bus_y}' x2='{cx + box_w // 2}' y2='{cy}' stroke='#64748b' stroke-width='2'/>"

            name = dev.get("Label") or dev.get("Hostname") or dev.get("Vendor") or "Host"
            ip = dev.get("IP", "")
            role = dev.get("DeviceType", "Device")
            status = dev.get("Status", "ONLINE").upper()

            border_color = "#10b981" if "ONLINE" in status or "ALIVE" in status else "#64748b"
            if "WARNING" in str(dev) or dev.get("RiskLevel") in ("HIGH", "CRITICAL"):
                border_color = "#ef4444"

            nodes_svg += f"""
            <g transform="translate({cx}, {cy})">
                <rect width="{box_w}" height="{box_h}" rx="8" fill="#151d2f" stroke="{border_color}" stroke-width="1.5"/>
                <text x="12" y="22" fill="#94a3b8" font-size="10" font-weight="bold" font-family="sans-serif">{html.escape(role[:20]).upper()}</text>
                <text x="12" y="42" fill="#ffffff" font-size="12" font-weight="bold" font-family="sans-serif">{html.escape(str(name)[:18])}</text>
                <text x="12" y="60" fill="#38bdf8" font-size="11" font-family="monospace">{html.escape(ip)}</text>
            </g>
            """

    total_h = bus_y + box_h + 100

    svg = f"""<svg width="100%" height="{total_h}" viewBox="0 0 {total_w} {total_h}" xmlns="http://www.w3.org/2000/svg" style="background:#0b0f19; border-radius:12px; border:1px solid #243048;">
        <defs>
            <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="1"/>
            </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
        {lines_svg}
        {nodes_svg}
    </svg>"""

    return svg


def export_topology_svg(devices, output_path, gateway_ip=None):
    """Saves generated network topology to a standalone SVG file."""
    svg_content = generate_topology_svg(devices, gateway_ip=gateway_ip)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"[+] Saved Network Topology diagram to: {output_path}")
