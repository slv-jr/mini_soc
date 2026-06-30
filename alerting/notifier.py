"""
alerting/notifier.py
Notifications multi-canal selon la sévérité : Slack, Telegram, webhook
générique, email SMTP. Chaque canal a son propre seuil de sévérité.
Les messages incluent les techniques MITRE et l'enrichissement threat-intel.
"""
import logging
import os
import smtplib
import threading
from email.mime.text import MIMEText

import httpx

from config import loader
from pipeline.schema import NetworkEvent, Severity

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

_SLACK_COLORS = {
    Severity.INFO: "#36a64f", Severity.LOW: "#a0d4fb", Severity.MEDIUM: "#f0a500",
    Severity.HIGH: "#e01e5a", Severity.CRITICAL: "#7b0099",
}
_EMOJIS = {
    Severity.INFO: ":information_source:", Severity.LOW: ":white_circle:",
    Severity.MEDIUM: ":warning:", Severity.HIGH: ":rotating_light:",
    Severity.CRITICAL: ":skull:",
}


def _severity_gte(sev: Severity, min_sev: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(sev) >= _SEVERITY_ORDER.index(Severity(min_sev))
    except ValueError:
        return True


def _mitre_str(event: NetworkEvent) -> str:
    return ", ".join(event.mitre) if event.mitre else "—"


def _geo_str(event: NetworkEvent) -> str:
    enr = event.enrichment or {}
    if not enr:
        return ""
    bits = []
    if enr.get("country"):
        bits.append(f"{enr.get('country')}")
    if enr.get("abuse_confidence") is not None:
        bits.append(f"AbuseIPDB {enr['abuse_confidence']}%")
    if enr.get("malicious"):
        bits.append("⚠ réputation malveillante")
    return " | ".join(bits)


class Notifier:
    def __init__(self):
        self._slack = loader.get("alerting.slack") or {}
        self._telegram = loader.get("alerting.telegram") or {}
        self._webhook = loader.get("alerting.webhook") or {}
        self._email = loader.get("alerting.email") or {}

        self._slack_url = os.environ.get("SLACK_WEBHOOK_URL", "")
        self._tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self._tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        self._smtp_user = os.environ.get("SMTP_USER", "")
        self._smtp_pass = os.environ.get("SMTP_PASSWORD", "")

    def notify(self, event: NetworkEvent) -> None:
        """Dispatch non bloquant (thread daemon)."""
        threading.Thread(target=self._dispatch, args=(event,), daemon=True).start()

    def _dispatch(self, event: NetworkEvent) -> None:
        if self._slack.get("enabled") and self._slack_url and \
                _severity_gte(event.severity, self._slack.get("min_severity", "medium")):
            self._send_slack(event)
        if self._telegram.get("enabled") and self._tg_token and self._tg_chat and \
                _severity_gte(event.severity, self._telegram.get("min_severity", "high")):
            self._send_telegram(event)
        if self._webhook.get("enabled") and self._webhook.get("url") and \
                _severity_gte(event.severity, self._webhook.get("min_severity", "high")):
            self._send_webhook(event)
        if self._email.get("enabled") and self._smtp_user and \
                _severity_gte(event.severity, self._email.get("min_severity", "high")):
            self._send_email(event)

    # ── Slack ──────────────────────────────────────────────────────────────────
    def _send_slack(self, event: NetworkEvent) -> None:
        geo = _geo_str(event)
        payload = {"attachments": [{
            "color": _SLACK_COLORS.get(event.severity, "#aaaaaa"),
            "title": f"{_EMOJIS.get(event.severity, ':bell:')} [{event.severity.value.upper()}] Mini-SOC",
            "text": event.message,
            "fields": [
                {"title": "Source IP", "value": event.src_ip or "—", "short": True},
                {"title": "MITRE", "value": _mitre_str(event), "short": True},
                {"title": "Type", "value": event.event_type.value, "short": True},
                {"title": "Threat intel", "value": geo or "—", "short": True},
            ],
            "footer": "Mini-SOC · Ubuntu",
        }]}
        self._post(self._slack_url, payload, "Slack")

    # ── Telegram ───────────────────────────────────────────────────────────────
    def _send_telegram(self, event: NetworkEvent) -> None:
        geo = _geo_str(event)
        text = (
            f"*Mini-SOC* [{event.severity.value.upper()}]\n"
            f"{event.message}\n"
            f"`src={event.src_ip or '-'}`  MITRE: {_mitre_str(event)}"
            + (f"\n_{geo}_" if geo else "")
        )
        try:
            httpx.post(
                f"https://api.telegram.org/bot{self._tg_token}/sendMessage",
                json={"chat_id": self._tg_chat, "text": text, "parse_mode": "Markdown"},
                timeout=5,
            )
        except Exception as e:
            logger.error(f"Telegram notification échouée: {e}")

    # ── Webhook générique ────────────────────────────────────────────────────
    def _send_webhook(self, event: NetworkEvent) -> None:
        payload = {
            "severity": event.severity.value,
            "message": event.message,
            "src_ip": event.src_ip,
            "event_type": event.event_type.value,
            "mitre": event.mitre,
            "enrichment": event.enrichment,
            "timestamp": event.timestamp.isoformat(),
        }
        self._post(self._webhook["url"], payload, "Webhook")

    def _post(self, url: str, payload: dict, name: str) -> None:
        try:
            resp = httpx.post(url, json=payload, timeout=5)
            if resp.status_code >= 300:
                logger.warning(f"{name} erreur {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.error(f"{name} notification échouée: {e}")

    # ── Email ──────────────────────────────────────────────────────────────────
    def _send_email(self, event: NetworkEvent) -> None:
        cfg = self._email
        if not all([cfg.get("smtp_host"), cfg.get("from_addr"), cfg.get("to_addrs")]):
            return
        body = (
            f"Mini-SOC — Alerte de sécurité\n"
            f"==============================\n"
            f"Sévérité   : {event.severity.value.upper()}\n"
            f"Type       : {event.event_type.value}\n"
            f"Source IP  : {event.src_ip or '—'}\n"
            f"MITRE      : {_mitre_str(event)}\n"
            f"Threat int.: {_geo_str(event) or '—'}\n"
            f"Horodatage : {event.timestamp.isoformat()}\n\n"
            f"{event.message}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = f"[Mini-SOC] {event.severity.value.upper()} — {event.src_ip or '?'}"
        msg["From"] = cfg["from_addr"]
        msg["To"] = ", ".join(cfg["to_addrs"])
        try:
            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 587), timeout=10) as smtp:
                smtp.starttls()
                smtp.login(self._smtp_user, self._smtp_pass)
                smtp.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())
            logger.info(f"Email envoyé pour alerte {event.event_id}")
        except Exception as e:
            logger.error(f"Email notification échouée: {e}")


_notifier: Notifier | None = None


def get_notifier() -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = Notifier()
    return _notifier
