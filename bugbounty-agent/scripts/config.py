#!/usr/bin/env python3
"""Centralized configuration loader.

Merges default `config.yaml` with optional per-target YAML files found in
`targets/<name>.yaml`. Environment variables (`.env`) always win for secrets.
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.yaml"
DEFAULT_CONFIG = {
    "recon": {
        "tools": {},
        "timeout": {},
        "rate_limit": {},
        "retries": {"max_attempts": 2, "backoff_seconds": 15},
    },
    "diffing": {},
    "notifications": {"max_items_per_section": 25},
    "dashboard": {"host": "127.0.0.1", "port": 8000},
    "reports": {"output_dir": "reports"},
}

load_dotenv(ROOT / ".env")


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge two dicts; override wins."""
    result = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config() -> dict:
    """Load default config.yaml merged with per-target overrides later."""
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f) or {}
    return _deep_merge(DEFAULT_CONFIG, cfg)


def load_target_config(target: str) -> dict:
    """Load per-target config from targets/<target>.yaml if it exists."""
    global_cfg = load_config()
    per_target = ROOT / "targets" / f"{target}.yaml"
    if per_target.exists():
        with open(per_target) as f:
            override = yaml.safe_load(f) or {}
        return _deep_merge(global_cfg, override)
    return global_cfg


def env(key: str, default=None):
    """Convenience wrapper for env vars (loaded from .env already)."""
    return os.environ.get(key, default)


if __name__ == "__main__":
    print(yaml.safe_dump(load_config(), sort_keys=False))
