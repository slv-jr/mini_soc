"""Tests du chargeur de configuration (expansion d'env + accès pointé)."""
from config import loader


def test_dotted_get_returns_nested_value():
    assert loader.get("redis.port") == 6379
    assert loader.get("redis.queues.raw_events") == "pisoc:raw"


def test_dotted_get_missing_returns_default():
    assert loader.get("does.not.exist", "fallback") == "fallback"
    assert loader.get("redis.nope") is None


def test_env_expansion(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_SECRET_TOKEN", "s3cr3t")
    cfg_file = tmp_path / "settings.yaml"
    cfg_file.write_text(
        "influxdb:\n  token: \"${MY_SECRET_TOKEN}\"\n  org: minisoc\n",
        encoding="utf-8",
    )
    data = loader.load(cfg_file)
    assert data["influxdb"]["token"] == "s3cr3t"
    # Restaure la config par défaut pour ne pas polluer les autres tests.
    loader.load()


def test_env_expansion_missing_var_becomes_empty(monkeypatch, tmp_path):
    monkeypatch.delenv("ABSENT_VAR", raising=False)
    cfg_file = tmp_path / "s.yaml"
    cfg_file.write_text("k: \"${ABSENT_VAR}\"\n", encoding="utf-8")
    data = loader.load(cfg_file)
    assert data["k"] == ""
    loader.load()


def test_default_syntax_used_when_var_absent(monkeypatch, tmp_path):
    monkeypatch.delenv("SOC_IFACE", raising=False)
    cfg_file = tmp_path / "s.yaml"
    cfg_file.write_text("iface: \"${SOC_IFACE:-eth0}\"\n", encoding="utf-8")
    data = loader.load(cfg_file)
    assert data["iface"] == "eth0"
    loader.load()


def test_default_syntax_overridden_by_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_IFACE", "enp19s0")
    cfg_file = tmp_path / "s.yaml"
    cfg_file.write_text("iface: \"${SOC_IFACE:-eth0}\"\n", encoding="utf-8")
    data = loader.load(cfg_file)
    assert data["iface"] == "enp19s0"
    loader.load()
