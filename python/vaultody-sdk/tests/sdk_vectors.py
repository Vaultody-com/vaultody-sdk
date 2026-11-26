"""Loads a shared vector set from test-vectors/ (four levels up from this file)."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VECTORS_DIR = ROOT / "test-vectors"


def load(name):
    return json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))


def ids(cases):
    return [vector["name"] for vector in cases]
