"""Configuration commune des tests : sys.path + chargement de la config."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import loader  # noqa: E402

loader.load(ROOT / "config" / "settings.yaml")
