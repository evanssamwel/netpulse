"""
Notification and Alert Dispatcher.
Supports Discord, Slack, Microsoft Teams, and generic HTTP JSON webhooks.
Uses standard urllib.request (zero third-party dependencies).
"""

import json
import urllib.request
from datetime import datetime


def send_webhook_alert(webhook_url, title, message, fields=None, severity="INFO"):
    """
    Dispatches a formatted alert payload to a Slack, Discord, or generic webhook.
    Returns:
        bool: True if delivered successfully, False otherwise.
    """
    if not webhook_url or not webhook_url.startswith("http"):
        return False

    color_hex = 0x38bdf8  # Default blue
    if severity == "WARNING":
        color_hex = 0xf59e0b  # Amber
    elif severity == "CRITICAL" or severity == "DANGER":
        color_hex = 0xef4444  # Red
    elif severity == "SUCCESS":
        color_hex = 0x10b981  # Green

    # Detect Discord webhook
    is_discord = "discord.com/api/webhooks" in webhook_url or "discordapp.com/api/webhooks" in webhook_url
    is_slack = "hooks.slack.com" in webhook_url

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if is_discord:
        discord_fields = []
        if fields:
            for k, v in fields.items():
                discord_fields.append({"name": str(k), "value": str(v), "inline": True})

        payload = {
            "embeds": [{
                "title": f"🛡 Network Scanner: {title}",
                "description": message,
                "color": color_hex,
                "fields": discord_fields,
                "footer": {"text": f"Event logged at {timestamp}"}
            }]
        }
    elif is_slack:
        payload = {
            "text": f"*{title}*\n{message}",
            "attachments": [{
                "color": f"#{color_hex:06x}",
                "fields": [{"title": k, "value": str(v), "short": True} for k, v in (fields or {}).items()]
            }]
        }
    else:
        # Generic JSON webhook
        payload = {
            "event": title,
            "message": message,
            "severity": severity,
            "timestamp": timestamp,
            "fields": fields or {}
        }

    try:
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "NetworkScannerSuite/2.0"
            }
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


def send_email_alert(smtp_server, smtp_port, sender, password, recipient, subject, body, use_tls=True):
    """
    Dispatches an alert email notification using Python's standard smtplib.
    Returns:
        bool: True if delivered successfully, False otherwise.
    """
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = f"[Network Scanner Alert] {subject}"
    msg["From"] = sender
    msg["To"] = recipient

    try:
        if use_tls:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=5) as server:
                server.starttls()
                if password:
                    server.login(sender, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=5) as server:
                if password:
                    server.login(sender, password)
                server.send_message(msg)
        return True
    except Exception:
        return False

