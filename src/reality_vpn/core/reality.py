# reality_pq.py
"""X25519MLKEM768 + Xray REALITY helpers."""
import struct
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from kyber_py.ml_kem import ML_KEM_768


from collections import OrderedDict as _OrderedDict

# Anti-replay кэш: session_id -> timestamp
_REPLAY_CACHE = _OrderedDict()
_REPLAY_CACHE_MAX = 20000

GROUP_X25519 = 0x001d
GROUP_X25519MLKEM768 = 0x11ec


def parse_hybrid_client_key_share(kdata):
    if len(kdata) != 32 + 1184:
        return None, None
    return kdata[:32], kdata[32:]


def gen_hybrid_server_key_share():
    x25519_priv = X25519PrivateKey.generate()
    x25519_pub = x25519_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    mlkem_ek, mlkem_dk = ML_KEM_768.keygen()
    return {
        "x25519_priv": x25519_priv,
        "x25519_pub": x25519_pub,
        "mlkem_ek": mlkem_ek,
        "mlkem_dk": mlkem_dk,
    }


def compute_hybrid_shared(server_keys, client_x25519_pub_bytes, client_mlkem_ek_bytes):
    client_x25519_pub = X25519PublicKey.from_public_bytes(client_x25519_pub_bytes)
    x25519_shared = server_keys["x25519_priv"].exchange(client_x25519_pub)
    mlkem_shared, mlkem_ct = ML_KEM_768.encaps(client_mlkem_ek_bytes)
    return x25519_shared + mlkem_shared, mlkem_ct


def build_hybrid_server_key_share(server_keys, mlkem_ct):
    return server_keys["x25519_pub"] + mlkem_ct


def _compute_auth_shared(static_priv_bytes, client_x25519_pub):
    """X25519(static_priv, client_pub) — Reality auth shared secret."""
    static_priv = X25519PrivateKey.from_private_bytes(static_priv_bytes)
    client_pub = X25519PublicKey.from_public_bytes(client_x25519_pub)
    return static_priv.exchange(client_pub)


def derive_auth_key(static_priv_bytes, client_x25519_pub, client_random):
    """
    AuthKey = HKDF-SHA256(IKM=X25519(static_priv, client_pub),
                          salt=client_random[:20], info="REALITY")
    """
    auth_shared = _compute_auth_shared(static_priv_bytes, client_x25519_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_random[:20],
        info=b"REALITY",
    ).derive(auth_shared)


def _check_replay(sid: bytes, ttl: int = 300) -> bool:
    """
    Возвращает True, если session_id УЖЕ видели (replay).
    Иначе регистрирует и возвращает False.
    """
    now = time.time()
    # Очистка старых
    while _REPLAY_CACHE:
        k, t = next(iter(_REPLAY_CACHE.items()))
        if now - t > ttl:
            _REPLAY_CACHE.popitem(last=False)
        else:
            break
    if sid in _REPLAY_CACHE:
        return True
    _REPLAY_CACHE[sid] = now
    if len(_REPLAY_CACHE) > _REPLAY_CACHE_MAX:
        _REPLAY_CACHE.popitem(last=False)
    return False


def verify_reality_session_id(static_priv_bytes, client_x25519_pub, sid, ch, cfg, verbose=False):
    """Расшифровывает session_id и проверяет short_id + timestamp."""
    cr = ch.get("random", b"")
    payload = ch.get("raw_client_hello", b"")

    if len(cr) < 32 or len(sid) != 32:
        return False

    try:
        auth_key = derive_auth_key(static_priv_bytes, client_x25519_pub, cr)
    except Exception as e:
        if verbose:
            print(f"[reality] auth_key error: {e}")
        return False

    nonce = cr[20:32]

    # AAD = ClientHello handshake-message с занулённым session_id
    # (payload УЖЕ без 5-байтового TLS record header)
    payload_zeroed = bytearray(payload)
    if len(payload_zeroed) > 39:
        sid_len_in_msg = payload_zeroed[38]
        for i in range(39, 39 + sid_len_in_msg):
            payload_zeroed[i] = 0
    payload_zeroed = bytes(payload_zeroed)

    try:
        pt = AESGCM(auth_key).decrypt(nonce, sid, payload_zeroed)
    except Exception as e:
        if verbose:
            print(f"[reality] decrypt fail: {type(e).__name__}")
        return False

    if len(pt) != 16:
        return False

    short_id = pt[8:16]
    expected = bytes.fromhex(cfg["short_id"])
    if short_id != expected:
        if verbose:
            print(f"[reality] short_id mismatch: {short_id.hex()} != {expected.hex()}")
        return False

    ts = struct.unpack(">I", pt[4:8])[0]
    now = int(time.time())
    diff = abs(now - ts)
    if diff > cfg.get("maxTimeDiff", 120):
        if verbose:
            print(f"[reality] timestamp off: diff={diff}s")
        return False

    # Anti-replay: session_id должен быть уникальным в пределах ttl
    ttl = max(diff, cfg.get("replay_ttl", 300))
    if _check_replay(sid, ttl=ttl):
        if verbose:
            print(f"[reality] REPLAY detected for sid={sid.hex()[:16]}...")
        return False

    if verbose:
        print(f"[reality] v{pt[0]}.{pt[1]}.{pt[2]} ts={ts} sid={short_id.hex()}")
    return True