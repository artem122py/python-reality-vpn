from reality_vpn.core.reality import (
    _compute_auth_shared,
    derive_auth_key,
    _check_replay,
    _REPLAY_CACHE,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


def _gen_keypair():
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_b, pub_b


def test_auth_shared_symmetric():
    """X25519(a_priv, b_pub) == X25519(b_priv, a_pub)."""
    a_priv, a_pub = _gen_keypair()
    b_priv, b_pub = _gen_keypair()

    shared_ab = _compute_auth_shared(a_priv, b_pub)
    shared_ba = _compute_auth_shared(b_priv, a_pub)

    assert shared_ab == shared_ba
    assert len(shared_ab) == 32


def test_auth_key_deterministic():
    """derive_auth_key даёт одинаковый результат при одинаковых входах."""
    a_priv, a_pub = _gen_keypair()
    b_priv, b_pub = _gen_keypair()
    cr = b"\x00" * 32

    k1 = derive_auth_key(a_priv, b_pub, cr)
    k2 = derive_auth_key(a_priv, b_pub, cr)

    assert k1 == k2
    assert len(k1) == 32


def test_auth_key_differs_with_random():
    """Разный client_random → разный auth_key."""
    a_priv, _ = _gen_keypair()
    _, b_pub = _gen_keypair()

    k1 = derive_auth_key(a_priv, b_pub, b"\x00" * 32)
    k2 = derive_auth_key(a_priv, b_pub, b"\x01" * 32)

    assert k1 != k2


def test_replay_cache():
    """Повторный session_id → replay=True."""
    _REPLAY_CACHE.clear()
    sid = b"test_sid_12345678901234567890abc"  # 32 байта

    first = _check_replay(sid, ttl=60)
    second = _check_replay(sid, ttl=60)

    assert first is False   # первый раз — ок
    assert second is True   # второй — replay
