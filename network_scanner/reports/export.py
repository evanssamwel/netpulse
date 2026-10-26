"""
Unified Scan Export Dispatcher.
Coordinates exports across JSON, CSV, and Interactive HTML.
"""

from network_scanner.reports.csv_report import export_csv
from network_scanner.reports.html_report import generate_html_report
from network_scanner.reports.json_report import export_json
from network_scanner.reports.topology import export_topology_svg, generate_topology_svg


def export_results(data, json_path=None, csv_path=None, html_path=None, svg_path=None, report_meta=None, risk_data=None, cve_data=None, theme=None):
    """Exports scan results to JSON, CSV, SVG topology, or standalone interactive HTML."""
    if json_path:
        export_json(data, json_path)

    if csv_path and data:
        export_csv(data, csv_path)

    gateway_ip = report_meta.get("gateway_ip") if report_meta else None
    topology_svg = ""
    if data and any("IP" in d and ("MAC" in d or "DeviceType" in d) for d in data):
        topology_svg = generate_topology_svg(data, gateway_ip=gateway_ip)

    if svg_path and data:
        export_topology_svg(data, svg_path, gateway_ip=gateway_ip)

    if html_path and report_meta:
        active_theme = theme or report_meta.get("theme", "dark")
        generate_html_report(
            title=report_meta.get("title", "Network Scan Audit"),
            scan_type=report_meta.get("scan_type", "SCAN"),
            target=report_meta.get("target", "Target"),
            stats=report_meta.get("stats", {}),
            items=data,
            output_path=html_path,
            risk_data=risk_data,
            cve_data=cve_data,
            topology_svg=topology_svg,
            theme=active_theme
        )
