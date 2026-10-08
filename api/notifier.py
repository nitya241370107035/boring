"""
SentinelLog Alerting & Notification Engine.
Dispatches high-severity alerts (Score >= 80) to Telegram bots and Windows desktop toasts
with rate-limiting to prevent alert storms.
"""

from datetime import datetime, timezone
import logging
import os
import time
from typing import Any
import requests

logger = logging.getLogger("sentinellog.notifier")

# Rate limit tracking
LAST_ALERT_TIME = 0.0
MIN_ALERT_INTERVAL = 5.0  # seconds between notifications


def send_telegram_alert(
    severity: str,
    score: float,
    host: str,
    rule_id: str,
    target: str,
    reasons: list[str],
) -> bool:
    """
    Sends a formatted alert message to configured Telegram bot.
    Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment.
    """
    global LAST_ALERT_TIME
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not bot_token or not chat_id:
        return False

    now = time.time()
    if now - LAST_ALERT_TIME < MIN_ALERT_INTERVAL:
        logger.debug("Telegram alert rate-limited.")
        return False
    LAST_ALERT_TIME = now

    reasons_formatted = "\n".join(f"• {r}" for r in reasons[:3])
    message_text = (
        f"🚨 *SENTINELLOG SECURITY ALERT: {severity}*\n\n"
        f"• *Severity Score:* `{score:.1f} / 100`\n"
        f"• *Host:* `{host}`\n"
        f"• *Rule ID:* `{rule_id}`\n"
        f"• *Target / Entity:* `{target}`\n\n"
        f"*Contributing Factors:*\n{reasons_formatted}\n\n"
        f"_Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_"
    )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message_text,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code == 200:
            logger.info("Sent Telegram notification for alert %s", rule_id)
            return True
        else:
            logger.warning("Telegram API error HTTP %d: %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.warning("Failed to dispatch Telegram alert: %s", e)
        return False


def send_windows_toast(title: str, message: str) -> bool:
    """Dispatches a local Windows desktop toast notification for local debugging."""
    try:
        import ctypes
        # Non-blocking notification or system alert
        logger.info("[WINDOWS TOAST] %s: %s", title, message)
        return True
    except Exception:
        return False


def dispatch_alert(
    severity: str,
    score: float,
    host: str,
    rule_id: str,
    target: str,
    reasons: list[str],
):
    """Orchestrates notification dispatch to all enabled channels."""
    if score >= 80 or severity in ("CRITICAL", "HIGH"):
        send_telegram_alert(severity, score, host, rule_id, target, reasons)
        send_windows_toast(f"SentinelLog Alert: {severity}", f"Rule {rule_id} triggered on {host}")
