"""Tests de l'authentification par token sur les endpoints POST du dashboard."""
import alerting.responder as resp_mod
import dashboard.topology as topo


def test_block_without_token_is_unauthorized(monkeypatch):
    monkeypatch.setattr(topo, "_API_TOKEN", "s3cr3t")
    client = topo.app.test_client()
    resp = client.post("/api/block", json={"ip": "1.2.3.4"})
    assert resp.status_code == 401


def test_block_with_wrong_token_is_unauthorized(monkeypatch):
    monkeypatch.setattr(topo, "_API_TOKEN", "s3cr3t")
    client = topo.app.test_client()
    resp = client.post("/api/block", json={"ip": "1.2.3.4"},
                       headers={"X-API-Token": "wrong"})
    assert resp.status_code == 401


def test_block_with_correct_token_passes_auth(monkeypatch):
    monkeypatch.setattr(topo, "_API_TOKEN", "s3cr3t")

    class _FakeResponder:
        def block_ip(self, ip, reason):
            return True

    monkeypatch.setattr(resp_mod, "get_responder", lambda: _FakeResponder())
    client = topo.app.test_client()
    resp = client.post("/api/block", json={"ip": "1.2.3.4"},
                       headers={"Authorization": "Bearer s3cr3t"})
    assert resp.status_code == 200
    assert resp.get_json()["ip"] == "1.2.3.4"


def test_endpoints_open_when_no_token_configured(monkeypatch):
    monkeypatch.setattr(topo, "_API_TOKEN", "")
    client = topo.app.test_client()
    # Sans IP -> 400 (validation), pas 401 : la porte est ouverte.
    resp = client.post("/api/block", json={})
    assert resp.status_code == 400
