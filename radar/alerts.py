from __future__ import annotations

import json
import os
import smtplib
from email.message import EmailMessage

import httpx


DEFAULT_EVENTS = {"new_program", "scope_added", "bounty_increased", "program_closed", "policy_dead"}


def format_events(events: list[dict], limit: int = 20) -> str:
    lines = []
    for event in events[:limit]:
        project = event.get("project") or "Unknown project"
        kind = event.get("type", "event")
        line = f"{kind}: {project}"
        if kind == "bounty_increased":
            line += f" — {event.get('old_value')} → {event.get('new_value')} USD"
        details = event.get("details")
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {}
        if kind == "scope_added" and isinstance(details, dict):
            added = details.get("added") or []
            line += f" — {len(added)} addition(s): " + ", ".join(added[:3])
        lines.append(line)
    if len(events) > limit:
        lines.append(f"… and {len(events) - limit} more")
    return "\n".join(lines)


def send_alerts(events: list[dict]) -> dict[str, int | str]:
    selected = [e for e in events if e.get("type") in DEFAULT_EVENTS]
    if not selected:
        return {"events": 0, "sent": 0}
    text = "Web3 Bounty Radar\n" + format_events(selected)
    sent = 0
    errors = []
    discord = os.getenv("DISCORD_WEBHOOK_URL")
    if discord:
        try:
            response = httpx.post(discord, json={"content": text[:1990]}, timeout=20)
            response.raise_for_status()
            sent += 1
        except httpx.HTTPError as exc:
            errors.append(f"Discord: {type(exc).__name__}")
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
    telegram_chat = os.getenv("TELEGRAM_CHAT_ID")
    if telegram_token and telegram_chat:
        try:
            response = httpx.post(
                f"https://api.telegram.org/bot{telegram_token}/sendMessage",
                json={"chat_id": telegram_chat, "text": text[:4000]}, timeout=20,
            )
            response.raise_for_status()
            sent += 1
        except httpx.HTTPError as exc:
            errors.append(f"Telegram: {type(exc).__name__}")
    smtp_host = os.getenv("SMTP_HOST")
    recipients = os.getenv("ALERT_EMAIL_TO")
    if smtp_host and recipients:
        try:
            message = EmailMessage()
            message["Subject"] = f"Web3 Bounty Radar: {len(selected)} change(s)"
            message["From"] = os.getenv("ALERT_EMAIL_FROM", os.getenv("SMTP_USERNAME", "radar@localhost"))
            message["To"] = recipients
            message.set_content(text)
            port = int(os.getenv("SMTP_PORT", "465"))
            if port == 465:
                server = smtplib.SMTP_SSL(smtp_host, port, timeout=20)
            else:
                server = smtplib.SMTP(smtp_host, port, timeout=20)
                server.starttls()
            with server:
                if os.getenv("SMTP_USERNAME"):
                    server.login(os.environ["SMTP_USERNAME"], os.environ.get("SMTP_PASSWORD", ""))
                server.send_message(message)
            sent += 1
        except (OSError, smtplib.SMTPException, ValueError) as exc:
            errors.append(f"Email: {type(exc).__name__}")
    return {"events": len(selected), "sent": sent, "errors": "; ".join(errors)}
