# vpnconfig.py
"""Обёртка над config.json: дефолты, валидация, доступ."""
import json
import os


import os as _os
PROJECT_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))))

DEFAULTS = {
    "dest": "ya.ru:443",
    "listen_port": 8443,
    "security": "reality",
    "clienthello_timeout": 5,
    "handshake_timeout": 10,
    "idle_timeout": 300,
    "maxTimeDiff": 120,
    "replay_ttl": 300,
    "use_vision": False,
    "sni_routes": {},
    "debug": False,
    "log_file": "",
    "stats_interval": 60,
    "traffic_limits_enabled": False,
    "traffic_limit_default": 0,
    "users": [],
}


class Config:
    def __init__(self, path=None):
        if path is None:
            path = _os.path.join(PROJECT_ROOT, "config.json")
        self.path = path
        self.data = {}

    def load(self):
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"config not found: {self.path}")
        with open(self.path) as f:
            self.data = json.load(f)
        self._apply_defaults()
        self._validate()
        return self.data

    def _apply_defaults(self):
        for k, v in DEFAULTS.items():
            if k not in self.data:
                self.data[k] = v

    def _validate(self):
        required = ["uuid", "private_key", "public_key", "short_id"]
        for k in required:
            if not self.data.get(k):
                raise ValueError(f"config: missing required field '{k}'")
        try:
            bytes.fromhex(self.data["private_key"])
            bytes.fromhex(self.data["public_key"])
        except Exception:
            raise ValueError("config: private_key/public_key must be hex")

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __getitem__(self, key):
        return self.data[key]

    def __contains__(self, key):
        return key in self.data


def load_config_file(path=None):
    cfg = Config(path)
    return cfg.load()
