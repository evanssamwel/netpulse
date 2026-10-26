"""
CSV Data Exporter.
"""

import csv


def export_csv(data, output_path):
    """Exports a list of host/port dictionaries to a CSV file."""
    if not data or not output_path:
        return

    fieldnames = list(data[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"[+] Saved CSV report to: {output_path}")
