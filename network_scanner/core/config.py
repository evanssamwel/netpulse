"""
Configuration Manager for NetPulse Suite.
Loads and persists user preferences (threads, timeouts, webhooks, default exports)
from scanner_config.json, ~/.config/netpulse/config.json, or ~/.config/network-scanner/config.json.
"""

import json
from pathlib import Path

LOCAL_CONFIG_FILE = Path("scanner_config.json")
GLOBAL_CONFIG_DIR = Path.home() / ".config" / "netpulse"
GLOBAL_CONFIG_FILE = GLOBAL_CONFIG_DIR / "config.json"
LEGACY_CONFIG_FILE = Path.home() / ".config" / "network-scanner" / "config.json"

DEFAULT_CONFIG = {
    "threads": 50,
    "timeout": 0.6,
    "udp_timeout": 1.5,
    "watch_interval": 15,
    "snmp_communities": ["public", "private", "community", "internal"],
    "webhook_url": "",
    "auto_resolve_hostnames": True,
    "record_history": True,
    "html_theme": "dark"
}


def load_config():
    """
    Loads configuration from local project directory or user home config.
    Returns merged config with defaults.
    """
    config = dict(DEFAULT_CONFIG)

    if LOCAL_CONFIG_FILE.exists():
        try:
            with open(LOCAL_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config.update(data)
                return config
        except Exception:
            pass

    if GLOBAL_CONFIG_FILE.exists():
        try:
            with open(GLOBAL_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config.update(data)
                return config
        except Exception:
            pass

    if LEGACY_CONFIG_FILE.exists():
        try:
            with open(LEGACY_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config.update(data)
                return config
        except Exception:
            pass

    return config


def save_config(config_dict, is_global=False):
    """Saves user configuration settings to disk."""
    if is_global:
        GLOBAL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        target = GLOBAL_CONFIG_FILE
    else:
        target = LOCAL_CONFIG_FILE

    with open(target, "w", encoding="utf-8") as f:
        json.dump(config_dict, f, indent=2)
    print(f"[+] Saved configuration to: {target}")
