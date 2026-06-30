"""Tests de l'enrichisseur (logique IP publique / privée, pas d'appel réseau)."""
from detection.enricher import Enricher


def test_is_public_classification():
    assert Enricher._is_public("8.8.8.8") is True
    assert Enricher._is_public("1.1.1.1") is True
    assert Enricher._is_public("192.168.1.10") is False
    assert Enricher._is_public("10.0.0.1") is False
    assert Enricher._is_public("127.0.0.1") is False
    assert Enricher._is_public("172.16.5.5") is False
    assert Enricher._is_public("not-an-ip") is False


def test_enrich_skips_private_ip():
    e = Enricher()
    assert e.enrich("192.168.1.50") == {}
    assert e.enrich(None) == {}


def test_enrich_public_ip_offline_returns_verdict():
    """Sans GeoIP ni clé API, l'enrichissement renvoie au moins ip + verdict."""
    e = Enricher()
    e._geoip_reader = None        # pas de base GeoIP en test
    e._abuse_enabled = False
    e._otx_enabled = False
    e._redis = None               # pas de cache
    result = e.enrich("8.8.8.8")
    assert result.get("ip") == "8.8.8.8"
    assert result.get("malicious") is False
