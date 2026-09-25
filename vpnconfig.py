# vpnconfig.py
"""Обёртка над config.json: дефолты, валидация, доступ."""
import json
import os


DEFAULTS = {
    "listen_port": 8443,
    "dest": "ya.ru:443",
    "security": "reality",
    "debug": False,
    "log_file": "",
    "maxTimeDiff": 120,
    "replay_ttl": 300,
    "clienthello_timeout": 5,
    "handshake_timeout": 10,
    "idle_timeout": 300,
    "stats_interval": 60,
}


class Config:
    def __init__(self, path="config.json"):
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


def load_config_file(path="config.json"):
    cfg = Config(path)
    return cfg.load()
