"""
alerting/responder.py
Couche SOAR : réponse automatique aux incidents.

Stratégie de blocage :
  1. si responder.prefer_wazuh_ar et l'API Wazuh est joignable -> active-response
     Wazuh (journalisée, déblocage temporisé géré par le manager) ;
  2. sinon, fallback : règle nftables locale sur l'hôte.

Sécurité : whitelist obligatoire, seuil de sévérité, durée limitée, toute
action est journalisée et persistée en base.
Remplace l'ancien alerting/remediation.py (iptables).
"""
import logging
import os
import subprocess
import threading
import time

import httpx

from config import loader
from pipeline.schema import NetworkEvent, Severity
from storage.sqlite_db import get_db

logger = logging.getLogger(__name__)

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_NFT_TABLE = "inet minisoc"
_NFT_SET = "blackhole"


def _sev_gte(sev: Severity, minimum: str) -> bool:
    try:
        return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(Severity(minimum))
    except ValueError:
        return True


class Responder:
    def __init__(self):
        cfg = loader.get("responder", {}) or {}
        self._auto_block = cfg.get("auto_block", False)
        self._prefer_wazuh = cfg.get("prefer_wazuh_ar", True)
        self._duration = cfg.get("block_duration_seconds", 3600)
        self._min_sev = cfg.get("min_severity", "high")
        self._whitelist = set(cfg.get("whitelist_ips", ["127.0.0.1"]))

        wcfg = loader.get("wazuh", {}) or {}
        self._wazuh_url = wcfg.get("api_url", "")
        self._wazuh_user = wcfg.get("api_user", "wazuh-wui")
        self._wazuh_pass = os.environ.get("WAZUH_API_PASSWORD", "")
        self._wazuh_verify = wcfg.get("verify_ssl", False)

        self._db = get_db()
        mode = "AUTO" if self._auto_block else "MANUEL (suggestion seule)"
        logger.info(f"Responder initialisé — mode {mode}, seuil={self._min_sev}")

    def handle_alert(self, event: NetworkEvent) -> bool:
        """Évalue une alerte/incident et applique un blocage si justifié."""
        ip = event.src_ip
        if not ip or ip in self._whitelist:
            return False
        if not _sev_gte(event.severity, self._min_sev):
            return False
        if self._db.is_blocked(ip):
            return False

        reason = f"{event.tags.get('chain', event.message or '')[:120]}"

        if not self._auto_block:
            logger.warning(
                f"REPONSE SUGGEREE: bloquer {ip} ({event.severity.value}). "
                f"Commande: nft add element {_NFT_TABLE} {_NFT_SET} '{{ {ip} }}'"
            )
            return False

        return self.block_ip(ip, reason)

    def block_ip(self, ip: str, reason: str) -> bool:
        if ip in self._whitelist:
            logger.error(f"REFUS: {ip} est en whitelist")
            return False

        ok = False
        if self._prefer_wazuh and self._wazuh_url and self._wazuh_pass:
            ok = self._block_via_wazuh(ip)
        if not ok:
            ok = self._block_via_nftables(ip)

        if ok:
            self._db.block_ip(ip, reason, self._duration)
            logger.warning(f"IP {ip} BLOQUEE ({self._duration}s) — {reason}")
            self._schedule_unblock(ip, self._duration)
        return ok

    # ── Backend Wazuh active-response ─────────────────────────────────────────
    def _block_via_wazuh(self, ip: str) -> bool:
        try:
            auth = httpx.post(
                f"{self._wazuh_url}/security/user/authenticate",
                auth=(self._wazuh_user, self._wazuh_pass),
                verify=self._wazuh_verify, timeout=5,
            )
            if auth.status_code != 200:
                return False
            token = auth.json().get("data", {}).get("token")
            resp = httpx.put(
                f"{self._wazuh_url}/active-response",
                headers={"Authorization": f"Bearer {token}"},
                json={"command": "minisoc-block-ip", "arguments": [ip],
                      "alert": {"data": {"srcip": ip}}},
                verify=self._wazuh_verify, timeout=5,
            )
            if resp.status_code in (200, 201):
                logger.info(f"Active-response Wazuh déclenchée pour {ip}")
                return True
        except Exception as e:
            logger.debug(f"Wazuh AR indisponible pour {ip}: {e}")
        return False

    # ── Backend nftables local (fallback) ─────────────────────────────────────
    def _block_via_nftables(self, ip: str) -> bool:
        try:
            subprocess.run(["nft", "list", "table", *_NFT_TABLE.split()],
                           capture_output=True, check=False)
            self._ensure_nft_set()
            subprocess.run(
                ["nft", "add", "element", *_NFT_TABLE.split(), _NFT_SET,
                 f"{{ {ip} timeout {self._duration}s }}"],
                check=True, capture_output=True,
            )
            logger.info(f"nftables: {ip} ajouté au set blackhole")
            return True
        except FileNotFoundError:
            logger.error("nft introuvable — installer nftables ou exécuter en root")
        except subprocess.CalledProcessError as e:
            logger.error(f"nftables échec pour {ip}: {e.stderr.decode(errors='replace')}")
        return False

    def _ensure_nft_set(self) -> None:
        table = _NFT_TABLE.split()
        subprocess.run(["nft", "add", "table", *table], capture_output=True, check=False)
        subprocess.run(
            ["nft", "add", "set", *table, _NFT_SET,
             "{ type ipv4_addr; flags timeout; }"],
            capture_output=True, check=False,
        )
        subprocess.run(
            ["nft", "add", "chain", *table, "input",
             "{ type filter hook input priority 0; }"],
            capture_output=True, check=False,
        )
        subprocess.run(
            ["nft", "add", "rule", *table, "input", "ip", "saddr", f"@{_NFT_SET}", "drop"],
            capture_output=True, check=False,
        )

    def unblock_ip(self, ip: str) -> bool:
        try:
            subprocess.run(
                ["nft", "delete", "element", *_NFT_TABLE.split(), _NFT_SET, f"{{ {ip} }}"],
                check=False, capture_output=True,
            )
            logger.info(f"IP {ip} débloquée")
            return True
        except Exception as e:
            logger.error(f"Échec déblocage {ip}: {e}")
            return False

    def _schedule_unblock(self, ip: str, delay: int) -> None:
        def _unblock():
            time.sleep(delay)
            self.unblock_ip(ip)
        threading.Thread(target=_unblock, daemon=True, name=f"unblock-{ip}").start()


_responder: Responder | None = None


def get_responder() -> Responder:
    global _responder
    if _responder is None:
        _responder = Responder()
    return _responder
