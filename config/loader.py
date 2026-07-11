"""
config/loader.py
Chargement et accès à la configuration centrale.

Toute la config spécifique à l'hôte (interface, sous-réseau, passerelle, hôtes
des services, secrets) vit dans l'environnement — jamais en dur dans le code.
Deux syntaxes sont supportées dans le YAML :
  ${VAR}            -> valeur de l'env, ou chaîne vide si absente
  ${VAR:-defaut}    -> valeur de l'env, ou "defaut" si absente/vide
"""
import logging
import os
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_config: dict = {}
_CONFIG_PATH = Path(__file__).parent / "settings.yaml"
# Capture VAR et un éventuel défaut après ":-".
_ENV_PATTERN = re.compile(r"\$\{(\w+)(?::-([^}]*))?\}")


def _sub_env(match: "re.Match") -> str:
    var, default = match.group(1), match.group(2)
    val = os.environ.get(var, "")
    if val == "" and default is not None:
        return default
    return val


def _expand_env(value):
    """Remplace récursivement les ${VAR} / ${VAR:-defaut} par l'environnement."""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(_sub_env, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load(path: str | Path | None = None) -> dict:
    global _config
    config_path = Path(path) if path else _CONFIG_PATH
    with open(config_path, encoding="utf-8") as f:
        _config = _expand_env(yaml.safe_load(f))
    logger.info(f"Configuration chargée depuis {config_path}")
    return _config


def get(key: str, default=None):
    """Accès par clé pointée ex: get('redis.host')"""
    keys = key.split(".")
    val = _config
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k, default)
    return val


def all_config() -> dict:
    return _config
