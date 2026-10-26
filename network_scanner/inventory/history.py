"""
Historical Inventory Tracking and Scan Change Detection.
Tracks FirstSeen, LastSeen, TimesSeen, and detects network configuration diffs.
"""

import json
from datetime import datetime
from network_scanner.constants import HISTORY_FILE


class ScanHistoryManager:
    """Tracks scan history to detect NEW, ONLINE, and OFFLINE devices, plus config changes."""

    @staticmethod
    def load_history():
        """Loads the complete persistent historical database."""
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data
            except Exception:
                return {"devices": {}, "last_scan": None}
        return {"devices": {}, "last_scan": None}

    @staticmethod
    def load_last_scan():
        """Returns the device map from the last scan session."""
        history = ScanHistoryManager.load_history()
        return history.get("devices", {})

    @staticmethod
    def record_scan(current_devices):
        """
        Updates the historical database with the current scan.
        Tracks first_seen, last_seen, times_seen, and last known attributes.
        """
        now_iso = datetime.now().isoformat()
        history = ScanHistoryManager.load_history()
        device_db = history.get("devices", {})

        for d in current_devices:
            ip = d.get("IP")
            if not ip:
                continue

            mac = d.get("MAC", "")
            vendor = d.get("Vendor", "")
            hostname = d.get("Hostname", "")
            device_type = d.get("DeviceType", "Unknown")

            if ip in device_db:
                record = device_db[ip]
                record["LastSeen"] = now_iso
                record["TimesSeen"] = record.get("TimesSeen", 1) + 1
                if mac and mac != record.get("MAC"):
                    record["PreviousMAC"] = record.get("MAC")
                    record["MAC"] = mac
                if vendor and vendor != "Unknown Vendor":
                    record["Vendor"] = vendor
                if hostname:
                    record["Hostname"] = hostname
                if device_type and device_type != "Unknown":
                    record["DeviceType"] = device_type
            else:
                device_db[ip] = {
                    "MAC": mac,
                    "Vendor": vendor,
                    "Hostname": hostname,
                    "DeviceType": device_type,
                    "FirstSeen": now_iso,
                    "LastSeen": now_iso,
                    "TimesSeen": 1
                }

        history["last_scan"] = now_iso
        history["devices"] = device_db

        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def diff_scan(current_devices):
        """
        Compares the current scan against previous history.
        Returns:
            dict: {
                "new": list,
                "online": list,
                "offline": list,
                "changes": list of change descriptions
            }
        """
        history = ScanHistoryManager.load_history()
        previous_devices = history.get("devices", {})
        current_ip_map = {d["IP"]: d for d in current_devices if "IP" in d}

        new_devices = []
        online_devices = []
        offline_devices = []
        changes = []

        for ip, d in current_ip_map.items():
            if ip not in previous_devices:
                d["Status"] = "NEW"
                d["FirstSeen"] = "Today"
                d["TimesSeen"] = 1
                new_devices.append(d)
                changes.append(f"[NEW] New device discovered: {ip} ({d.get('MAC', 'No MAC')})")
            else:
                prev = previous_devices[ip]
                d["Status"] = "ONLINE"
                d["FirstSeen"] = prev.get("FirstSeen", "Unknown")[:10]
                d["TimesSeen"] = prev.get("TimesSeen", 0) + 1
                online_devices.append(d)

                # Check for MAC address change (Potential ARP Spoofing / IP reassignment)
                current_mac = d.get("MAC")
                prev_mac = prev.get("MAC")
                if current_mac and prev_mac and current_mac.lower() != prev_mac.lower():
                    change_msg = f"[WARN] MAC address changed for {ip}: was {prev_mac}, now {current_mac}!"
                    changes.append(change_msg)
                    d["MAC_Changed"] = True

                # Check for Hostname change
                current_host = d.get("Hostname")
                prev_host = prev.get("Hostname")
                if current_host and prev_host and current_host != prev_host:
                    changes.append(f"[INFO] Hostname changed for {ip}: was '{prev_host}', now '{current_host}'")

        # Determine offline devices
        if previous_devices:
            for ip, prev in previous_devices.items():
                if ip not in current_ip_map:
                    offline_devices.append({
                        "IP": ip,
                        "MAC": prev.get("MAC", "Unknown"),
                        "Vendor": prev.get("Vendor", "Unknown"),
                        "Hostname": prev.get("Hostname", ""),
                        "DeviceType": prev.get("DeviceType", "Unknown"),
                        "Label": "",
                        "Notes": "",
                        "Status": "OFFLINE",
                        "FirstSeen": prev.get("FirstSeen", "Unknown")[:10],
                        "LastSeen": prev.get("LastSeen", "Unknown")[:10],
                        "TimesSeen": prev.get("TimesSeen", 1)
                    })

        return {
            "new": new_devices,
            "online": online_devices,
            "offline": offline_devices,
            "changes": changes
        }
