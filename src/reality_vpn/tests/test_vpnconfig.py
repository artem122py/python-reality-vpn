import json
import pytest
from reality_vpn.cli.config import Config, DEFAULTS


def _write_cfg(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


def _valid_cfg():
    return {
        "uuid": "00000000-0000-0000-0000-000000000001",
        "private_key": "aa" * 32,
        "public_key": "bb" * 32,
        "short_id": "0011223344556677",
    }


def test_loads_valid(tmp_path):
    p = tmp_path / "config.json"
    _write_cfg(p, _valid_cfg())

    cfg = Config(str(p))
    data = cfg.load()

    assert data["uuid"].endswith("0001")
    assert cfg.get("listen_port") == DEFAULTS["listen_port"]


def test_missing_required(tmp_path):
    p = tmp_path / "config.json"
    _write_cfg(p, {"uuid": "x"})

    cfg = Config(str(p))
    with pytest.raises(ValueError):
        cfg.load()


def test_bad_hex(tmp_path):
    p = tmp_path / "config.json"
    cfg_data = _valid_cfg()
    cfg_data["private_key"] = "not-hex"

    _write_cfg(p, cfg_data)
    cfg = Config(str(p))
    with pytest.raises(ValueError):
        cfg.load()


def test_defaults_applied(tmp_path):
    p = tmp_path / "config.json"
    _write_cfg(p, _valid_cfg())

    cfg = Config(str(p))
    data = cfg.load()

    for k, v in DEFAULTS.items():
        assert k in data
