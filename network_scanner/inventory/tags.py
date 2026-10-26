"""
Manages friendly device labels, aliases, and persistent user notes.
"""

import json
from datetime import datetime
from network_scanner.constants import TAGS_FILE


class DeviceTagManager:
    """Manages custom user notes and labels for discovered devices."""

    @staticmethod
    def load_tags():
        if TAGS_FILE.exists():
            try:
                with open(TAGS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    @staticmethod
    def save_tags(tags):
        with open(TAGS_FILE, "w", encoding="utf-8") as f:
            json.dump(tags, f, indent=2)

    @classmethod
    def set_tag(cls, identifier, label, notes=""):
        tags = cls.load_tags()
        tags[identifier] = {
            "label": label,
            "notes": notes,
            "updated_at": datetime.now().isoformat()
        }
        cls.save_tags(tags)

    @classmethod
    def get_tag(cls, *identifiers):
        tags = cls.load_tags()
        for ident in identifiers:
            if ident and ident in tags:
                return tags[ident]
        return None

    @classmethod
    def delete_tag(cls, identifier):
        tags = cls.load_tags()
        if identifier in tags:
            del tags[identifier]
            cls.save_tags(tags)
            return True
        return False
