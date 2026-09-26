# genconf.py
import os
import json
import secrets
import uuid as uuidlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


CONFIG_PATH = "config.json"


def gen_uuid():
    return str(uuidlib.uuid4())


def gen_short_id():
    return secrets.token_hex(8)


def gen_x25519():
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def gen_config():
    """Сгенерировать канонический config.json для 2.1.0."""
    print("Config not found, generating...")
    priv, pub = gen_x25519()
    cfg = {
        # обязательные
        "uuid": gen_uuid(),
        "private_key": priv.hex(),
        "public_key": pub.hex(),
        "short_id": gen_short_id(),

        # основное
        "dest": "ya.ru:443",
        "listen_port": 8443,
        "security": "reality",

        # тайминги
        "clienthello_timeout": 5,
        "handshake_timeout": 10,
        "idle_timeout": 300,
        "maxTimeDiff": 120,
        "replay_ttl": 300,

        # XTLS-Vision (BETA, off by default)
        "use_vision": False,

        # SNI-routing
        "sni_routes": {},

        # логи
        "debug": False,
        "log_file": "",
        "stats_interval": 60,

        # лимиты трафика
        "traffic_limits_enabled": False,
        "traffic_limit_default": 0,

        # single-user (пустой список)
        "users": [],
    }
    save_config(cfg)
    print(f"Config written to {CONFIG_PATH}")
    print(f"  uuid       = {cfg['uuid']}")
    print(f"  public_key = {cfg['public_key']}")
    print(f"  short_id   = {cfg['short_id']}")
    print(f"  dest       = {cfg['dest']}")
    print(f"  use_vision = {cfg['use_vision']}")
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def load_config(noconfig=False):
    if noconfig or not os.path.exists(CONFIG_PATH):
        return gen_config()
    with open(CONFIG_PATH) as f:
        return json.load(f)