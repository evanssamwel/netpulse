"""
JSON Data Exporter.
"""

import json


def export_json(data, output_path):
    """Exports structured scan data to a formatted JSON file."""
    if not output_path:
        return

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved JSON report to: {output_path}")
