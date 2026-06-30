"""
detection/enricher.py
Enrichissement threat-intel des adresses IP publiques :
  - GeoIP (MaxMind GeoLite2, base locale offline)
  - AbuseIPDB (score de réputation, free tier)
  - AlienVault OTX (optionnel)

Résultats mis en cache dans Redis (TTL configurable) pour limiter les appels
API. Les IP privées/réservées sont ignorées (pas d'intérêt threat-intel).
"""
import ipaddress
import json
import logging
import os

import httpx
import redis

from config import loader

logger = logging.getLogger(__name__)


class Enricher:
    def __init__(self):
        cfg = loader.get("enrichment", {}) or {}
        self._enabled = cfg.get("enabled", True)
        self._cache_ttl = cfg.get("cache_ttl_seconds", 86400)

        geo_cfg = cfg.get("geoip", {}) or {}
        self._geoip_enabled = geo_cfg.get("enabled", True)
        self._geoip_db_path = geo_cfg.get("db_path", "data/geoip/GeoLite2-City.mmdb")
        self._geoip_reader = None

        abuse_cfg = cfg.get("abuseipdb", {}) or {}
        self._abuse_enabled = abuse_cfg.get("enabled", False)
        self._abuse_min_conf = abuse_cfg.get("min_confidence", 50)
        self._abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")

        otx_cfg = cfg.get("otx", {}) or {}
        self._otx_enabled = otx_cfg.get("enabled", False)
        self._otx_key = os.environ.get("OTX_API_KEY", "")

        redis_cfg = loader.get("redis", {}) or {}
        try:
            self._redis = redis.Redis(
                host=redis_cfg.get("host", "localhost"),
                port=redis_cfg.get("port", 6379),
                db=redis_cfg.get("db", 0),
                decode_responses=True,
                socket_connect_timeout=3,
            )
        except redis.RedisError as e:
            logger.warning(f"Cache Redis indisponible pour l'enrichissement: {e}")
            self._redis = None

        self._init_geoip()

    def _init_geoip(self) -> None:
        if not self._geoip_enabled:
            return
        try:
            import geoip2.database
            self._geoip_reader = geoip2.database.Reader(self._geoip_db_path)
            logger.info(f"GeoIP chargé: {self._geoip_db_path}")
        except FileNotFoundError:
            logger.warning(f"Base GeoIP absente: {self._geoip_db_path} (GeoIP désactivé)")
            self._geoip_reader = None
        except ImportError:
            logger.warning("Module geoip2 non installé (GeoIP désactivé)")
            self._geoip_reader = None
        except Exception as e:  # base corrompue, etc.
            logger.warning(f"Échec chargement GeoIP: {e}")
            self._geoip_reader = None

    @staticmethod
    def _is_public(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback or addr.is_reserved
                        or addr.is_multicast or addr.is_link_local)
        except ValueError:
            return False

    def enrich(self, ip: str | None) -> dict:
        """Retourne un dict d'enrichissement pour une IP (vide si IP privée/désactivé)."""
        if not self._enabled or not ip or not self._is_public(ip):
            return {}

        cached = self._cache_get(ip)
        if cached is not None:
            return cached

        result: dict = {"ip": ip}
        result.update(self._geoip(ip))
        if self._abuse_enabled and self._abuse_key:
            result.update(self._abuseipdb(ip))
        if self._otx_enabled and self._otx_key:
            result.update(self._otx(ip))

        # Verdict synthétique réutilisé par l'alerting / le dashboard.
        result["malicious"] = bool(
            result.get("abuse_confidence", 0) >= self._abuse_min_conf
            or result.get("otx_pulses", 0) > 0
        )

        self._cache_set(ip, result)
        return result

    # ── Sources ──────────────────────────────────────────────────────────────
    def _geoip(self, ip: str) -> dict:
        if not self._geoip_reader:
            return {}
        try:
            r = self._geoip_reader.city(ip)
            return {
                "country": r.country.iso_code,
                "country_name": r.country.name,
                "city": r.city.name,
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
            }
        except Exception:
            return {}

    def _abuseipdb(self, ip: str) -> dict:
        try:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "abuse_total_reports": d.get("totalReports", 0),
                    "abuse_isp": d.get("isp"),
                    "abuse_domain": d.get("domain"),
                }
            logger.debug(f"AbuseIPDB {ip}: HTTP {resp.status_code}")
        except Exception as e:
            logger.debug(f"AbuseIPDB échec pour {ip}: {e}")
        return {}

    def _otx(self, ip: str) -> dict:
        try:
            resp = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self._otx_key},
                timeout=5,
            )
            if resp.status_code == 200:
                d = resp.json()
                return {"otx_pulses": d.get("pulse_info", {}).get("count", 0)}
        except Exception as e:
            logger.debug(f"OTX échec pour {ip}: {e}")
        return {}

    # ── Cache Redis ────────────────────────────────────────────────────────────
    def _cache_get(self, ip: str) -> dict | None:
        if not self._redis:
            return None
        try:
            raw = self._redis.get(f"pisoc:enrich:{ip}")
            return json.loads(raw) if raw else None
        except (redis.RedisError, json.JSONDecodeError):
            return None

    def _cache_set(self, ip: str, data: dict) -> None:
        if not self._redis:
            return
        try:
            self._redis.set(f"pisoc:enrich:{ip}", json.dumps(data), ex=self._cache_ttl)
        except redis.RedisError:
            pass


_enricher: Enricher | None = None


def get_enricher() -> Enricher:
    global _enricher
    if _enricher is None:
        _enricher = Enricher()
    return _enricher
