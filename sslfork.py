# sslfork.py
"""TLS 1.3 сервер с Xray-совместимой Reality-аутентификацией."""
import asyncio
import struct
import hashlib
import hmac
import os
import datetime

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from vpnlog import log
from reality_pq import (
    parse_hybrid_client_key_share,
    gen_hybrid_server_key_share,
    compute_hybrid_shared,
    build_hybrid_server_key_share,
    verify_reality_session_id,
    GROUP_X25519,
    GROUP_X25519MLKEM768,
)


# ---------- TLS constants ----------

CONTENT_CHANGE_CIPHER_SPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17

HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_ENCRYPTED_EXTENSIONS = 0x08
HS_CERTIFICATE = 0x0b
HS_CERTIFICATE_VERIFY = 0x0f
HS_FINISHED = 0x14

CIPHER_AES_128_GCM_SHA256 = 0x1301


# ---------- Reality certificate (constant ed25519 key + HMAC signature) ----------

_REALITY_ED_PRIV = None
_REALITY_CERT_TEMPLATE = None


def _init_reality_cert():
    """
    Однократная инициализация: постоянный ed25519 ключ + шаблон сертификата.
    В Xray REALITY генерирует ed25519 один раз при старте сервера,
    а подпись сертификата вычисляется через HMAC(AuthKey, ed25519_pub).
    """
    global _REALITY_ED_PRIV, _REALITY_CERT_TEMPLATE
    if _REALITY_ED_PRIV is not None:
        return

    _REALITY_ED_PRIV = Ed25519PrivateKey.generate()
    ed_pub = _REALITY_ED_PRIV.public_key()

    subject_empty = x509.Name([])
    t_zero = datetime.datetime(1950, 1, 1, 0, 0, 0)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_empty)
        .issuer_name(subject_empty)
        .public_key(ed_pub)
        .serial_number(1)
        .not_valid_before(t_zero)
        .not_valid_after(t_zero)
        .sign(_REALITY_ED_PRIV, None)
    )
    _REALITY_CERT_TEMPLATE = bytearray(cert.public_bytes(serialization.Encoding.DER))


def _gen_reality_cert(auth_key):
    """
    Возвращает (der, ed_priv). Заменяет последние 64 байта подписи
    на HMAC-SHA512(auth_key, ed25519_public_key).
    """
    _init_reality_cert()
    der = bytearray(_REALITY_CERT_TEMPLATE)

    ed_pub = _REALITY_ED_PRIV.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    mac = hmac.new(auth_key, ed_pub, hashlib.sha512).digest()
    der[-64:] = mac
    return bytes(der), _REALITY_ED_PRIV


# ---------- TLS record layer ----------

async def _read_tls_record(reader):
    hdr = await reader.readexactly(5)
    ctype = hdr[0]
    length = struct.unpack(">H", hdr[3:5])[0]
    payload = await reader.readexactly(length)
    return ctype, payload, hdr


def _pack_tls_record(ctype, payload):
    return bytes([ctype]) + struct.pack(">HH", 0x0303, len(payload)) + payload


def _hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret, label, context, length):
    full_label = b"tls13 " + label
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label).derive(secret)


class _RecordCipher:
    """AES-128-GCM обёртка для TLS 1.3 record layer."""

    def __init__(self, key, iv):
        self.aead = AESGCM(key)
        self.iv = iv
        self.seq = 0

    def _nonce(self):
        seq_bytes = self.seq.to_bytes(8, "big")
        nonce = bytearray(self.iv)
        for i in range(8):
            nonce[-1 - i] ^= seq_bytes[-1 - i]
        return bytes(nonce)

    def encrypt(self, content_type, plaintext):
        inner = plaintext + bytes([content_type])
        ct_len = len(inner) + 16
        aad = bytes([CONTENT_APPLICATION_DATA]) + struct.pack(">HH", 0x0303, ct_len)
        ct = self.aead.encrypt(self._nonce(), inner, aad)
        self.seq += 1
        return aad + ct

    def decrypt(self, ct, aad):
        inner = self.aead.decrypt(self._nonce(), ct, aad)
        self.seq += 1
        return inner[-1], inner[:-1]


# ---------- ClientHello parsing ----------

def _parse_client_hello(payload):
    assert payload[0] == HS_CLIENT_HELLO
    body = payload[4:]

    legacy_version = struct.unpack(">H", body[0:2])[0]
    random = body[2:34]
    sid_len = body[34]
    session_id = body[35:35 + sid_len]
    pos = 35 + sid_len

    cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    cipher_suites = [struct.unpack(">H", body[pos + i:pos + i + 2])[0] for i in range(0, cs_len, 2)]
    pos += cs_len

    comp_len = body[pos]
    pos += 1 + comp_len

    ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_len

    key_share = None
    key_share_hybrid = None
    key_share_group = None
    sni = None
    supported_versions = []
    signature_algorithms = []

    while pos < ext_end:
        etype = struct.unpack(">H", body[pos:pos + 2])[0]
        elen = struct.unpack(">H", body[pos + 2:pos + 4])[0]
        edata = body[pos + 4:pos + 4 + elen]
        pos += 4 + elen

        if etype == 0x0033:  # key_share
            shares_len = struct.unpack(">H", edata[0:2])[0]
            p = 2
            while p < 2 + shares_len:
                group = struct.unpack(">H", edata[p:p + 2])[0]
                klen = struct.unpack(">H", edata[p + 2:p + 4])[0]
                kdata = edata[p + 4:p + 4 + klen]
                if group == GROUP_X25519:
                    key_share = kdata
                    key_share_group = GROUP_X25519
                elif group == GROUP_X25519MLKEM768:
                    key_share_hybrid = kdata
                    key_share_group = GROUP_X25519MLKEM768
                p += 4 + klen

        elif etype == 0x0000:  # server_name
            if len(edata) >= 5:
                name_len = struct.unpack(">H", edata[3:5])[0]
                sni = edata[5:5 + name_len].decode("ascii", "replace")

        elif etype == 0x000d:  # signature_algorithms
            if len(edata) >= 2:
                slen = struct.unpack(">H", edata[0:2])[0]
                p2 = 2
                while p2 + 2 <= 2 + slen and p2 + 2 <= len(edata):
                    signature_algorithms.append(struct.unpack(">H", edata[p2:p2 + 2])[0])
                    p2 += 2

        elif etype == 0x002b:  # supported_versions
            if len(edata) >= 1:
                svlen = edata[0]
                supported_versions = [
                    struct.unpack(">H", edata[1 + i:3 + i])[0]
                    for i in range(0, svlen, 2)
                ]

    return {
        "legacy_version": legacy_version,
        "random": random,
        "session_id": session_id,
        "cipher_suites": cipher_suites,
        "key_share": key_share,
        "key_share_hybrid": key_share_hybrid,
        "key_share_group": key_share_group,
        "sni": sni,
        "supported_versions": supported_versions,
        "signature_algorithms": signature_algorithms,
        "raw_client_hello": payload,
    }


# ---------- Reality fallback ----------

async def _fallback_to_dest(reader, writer, cfg, initial_bytes):
    """Прозрачный TCP-форвард на dest."""
    try:
        host, port = cfg["dest"].rsplit(":", 1)
        port = int(port)
    except Exception:
        try: writer.close()
        except Exception: pass
        return

    try:
        r_reader, r_writer = await asyncio.open_connection(host, port)
    except Exception:
        try: writer.close()
        except Exception: pass
        return

    try:
        if initial_bytes:
            r_writer.write(initial_bytes)
            await r_writer.drain()
    except Exception:
        pass

    async def pipe(r, w):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try: w.close()
            except Exception: pass

    await asyncio.gather(
        pipe(reader, r_writer),
        pipe(r_reader, writer),
        return_exceptions=True,
    )


# ---------- Main handshake ----------

async def wrap_server(reader, writer, cfg):
    """TLS 1.3 handshake + Reality. Возвращает (secure_reader, secure_writer) или (None, None)."""
    if cfg.get("security", "tls") == "none":
        return reader, writer

    _init_reality_cert()

    peer = writer.get_extra_info("peername")
    try:
        # Таймаут на чтение ClientHello
        ch_timeout = cfg.get("clienthello_timeout", 5)
        try:
            ctype, payload, hdr = await asyncio.wait_for(
                _read_tls_record(reader), timeout=ch_timeout
            )
        except asyncio.TimeoutError:
            log.warn(f"[sslfork] {peer}: ClientHello timeout ({ch_timeout}s)")
            try: writer.close()
            except Exception: pass
            return None, None

        raw_first = hdr + payload

        if ctype != CONTENT_HANDSHAKE:
            log.debug(f"[sslfork] {peer}: non-handshake, fallback")
            await _fallback_to_dest(reader, writer, cfg, raw_first)
            return None, None

        hs_timeout = cfg.get("handshake_timeout", 10)
        try:
            return await asyncio.wait_for(
                _do_handshake(reader, writer, cfg, payload, raw_first, peer),
                timeout=hs_timeout,
            )
        except asyncio.TimeoutError:
            log.warn(f"[sslfork] {peer}: handshake timeout ({hs_timeout}s)")
            try: writer.close()
            except Exception: pass
            return None, None

    except asyncio.IncompleteReadError:
        # клиент закрыл соединение до ClientHello — норма, не ошибка
        log.debug("[sslfork] client closed before ClientHello")
        return None, None
    except Exception as e:
        log.error(f"[sslfork] handshake failed: {type(e).__name__}: {e}")
        return None, None


async def _do_handshake(reader, writer, cfg, payload, raw_first, peer):
    """Вся логика после чтения ClientHello, с таймаутом."""
    try:
        ch = _parse_client_hello(payload)
        group = ch.get("key_share_group")

        static_priv_bytes = bytes.fromhex(cfg["private_key"])
        server_pub_hybrid = None
        server_pub = None
        auth_ok = False

        # --- Обмен ключами ---
        if group == GROUP_X25519MLKEM768 and ch.get("key_share_hybrid"):
            client_x25519_pub, client_mlkem_ek = parse_hybrid_client_key_share(ch["key_share_hybrid"])
            if client_x25519_pub is None:
                await _fallback_to_dest(reader, writer, cfg, raw_first)
                return None, None
            server_keys = gen_hybrid_server_key_share()
            combined_shared, mlkem_ct = compute_hybrid_shared(server_keys, client_x25519_pub, client_mlkem_ek)
            server_pub_hybrid = build_hybrid_server_key_share(server_keys, mlkem_ct)
            shared = combined_shared
            auth_ok = verify_reality_session_id(static_priv_bytes, client_x25519_pub, ch["session_id"], ch, cfg)
        elif ch.get("key_share") is not None:
            client_pub = X25519PublicKey.from_public_bytes(ch["key_share"])
            server_priv = X25519PrivateKey.generate()
            server_pub = server_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            shared = server_priv.exchange(client_pub)
            auth_ok = verify_reality_session_id(static_priv_bytes, ch["key_share"], ch["session_id"], ch, cfg)
        else:
            await _fallback_to_dest(reader, writer, cfg, raw_first)
            return None, None

        if not auth_ok:
            await _fallback_to_dest(reader, writer, cfg, raw_first)
            return None, None

        # --- AuthKey для сертификата (static × client ephemeral, HKDF) ---
        static_priv = X25519PrivateKey.from_private_bytes(static_priv_bytes)
        client_pub_obj = X25519PublicKey.from_public_bytes(ch["key_share"])
        auth_shared = static_priv.exchange(client_pub_obj)
        auth_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=ch["random"][:20], info=b"REALITY",
        ).derive(auth_shared)

        # --- ServerHello ---
        server_random = os.urandom(32)
        session_id = ch["session_id"]

        sh_ext = bytearray()
        sh_ext += struct.pack(">HH", 0x002b, 2) + struct.pack(">H", 0x0304)
        if server_pub_hybrid is not None:
            ks_group = GROUP_X25519MLKEM768
            ks_data = server_pub_hybrid
        else:
            ks_group = GROUP_X25519
            ks_data = server_pub
        ks_body = struct.pack(">HH", ks_group, len(ks_data)) + ks_data
        sh_ext += struct.pack(">HH", 0x0033, len(ks_body)) + ks_body

        sh_body = (
            struct.pack(">H", 0x0303)
            + server_random
            + bytes([len(session_id)]) + session_id
            + struct.pack(">H", CIPHER_AES_128_GCM_SHA256)
            + b"\x00"
            + struct.pack(">H", len(sh_ext)) + bytes(sh_ext)
        )
        sh_msg = bytes([HS_SERVER_HELLO]) + len(sh_body).to_bytes(3, "big") + sh_body

        # --- Key schedule ---
        empty_hash = hashlib.sha256(b"").digest()
        early_secret = _hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        derived = _hkdf_expand_label(early_secret, b"derived", empty_hash, 32)
        handshake_secret = _hkdf_extract(derived, shared)

        transcript_ch_sh = payload + sh_msg
        chs_hash = hashlib.sha256(transcript_ch_sh).digest()

        c_hs_secret = _hkdf_expand_label(handshake_secret, b"c hs traffic", chs_hash, 32)
        s_hs_secret = _hkdf_expand_label(handshake_secret, b"s hs traffic", chs_hash, 32)

        c_hs_key = _hkdf_expand_label(c_hs_secret, b"key", b"", 16)
        c_hs_iv = _hkdf_expand_label(c_hs_secret, b"iv", b"", 12)
        s_hs_key = _hkdf_expand_label(s_hs_secret, b"key", b"", 16)
        s_hs_iv = _hkdf_expand_label(s_hs_secret, b"iv", b"", 12)

        client_hs_cipher = _RecordCipher(c_hs_key, c_hs_iv)
        server_hs_cipher = _RecordCipher(s_hs_key, s_hs_iv)

        writer.write(_pack_tls_record(CONTENT_HANDSHAKE, sh_msg))
        await writer.drain()

        # --- EncryptedExtensions ---
        ee_body = struct.pack(">H", 0)
        ee_msg = bytes([HS_ENCRYPTED_EXTENSIONS]) + len(ee_body).to_bytes(3, "big") + ee_body

        # --- Certificate (Reality: HMAC-подпись) ---
        cert_der, ed_priv = _gen_reality_cert(auth_key)
        cert_entry = len(cert_der).to_bytes(3, "big") + cert_der + struct.pack(">H", 0)
        cert_list = len(cert_entry).to_bytes(3, "big") + cert_entry
        cert_body = b"\x00" + cert_list
        cert_msg = bytes([HS_CERTIFICATE]) + len(cert_body).to_bytes(3, "big") + cert_body

        # --- CertificateVerify (ed25519 постоянным ключом) ---
        transcript_for_cv = transcript_ch_sh + ee_msg + cert_msg
        cv_context = (
            b" " * 64
            + b"TLS 1.3, server CertificateVerify\x00"
            + hashlib.sha256(transcript_for_cv).digest()
        )
        cv_sig = ed_priv.sign(cv_context)
        cv_body = struct.pack(">H", 0x0807) + struct.pack(">H", len(cv_sig)) + cv_sig
        cv_msg = bytes([HS_CERTIFICATE_VERIFY]) + len(cv_body).to_bytes(3, "big") + cv_body

        # --- Finished ---
        transcript_before_fin = transcript_for_cv + cv_msg
        fin_key = _hkdf_expand_label(s_hs_secret, b"finished", b"", 32)
        fin_verify = hmac.new(fin_key, hashlib.sha256(transcript_before_fin).digest(), hashlib.sha256).digest()
        fin_msg = bytes([HS_FINISHED]) + len(fin_verify).to_bytes(3, "big") + fin_verify

        all_server_hs = ee_msg + cert_msg + cv_msg + fin_msg
        enc = server_hs_cipher.encrypt(CONTENT_HANDSHAKE, all_server_hs)
        writer.write(enc)
        await writer.drain()

        # --- Client Finished ---
        while True:
            ct, raw, hdr2 = await _read_tls_record(reader)
            if ct == CONTENT_CHANGE_CIPHER_SPEC:
                continue
            if ct == CONTENT_APPLICATION_DATA:
                break
            if ct == CONTENT_ALERT:
                return None, None
            return None, None

        inner_ct, inner_pt = client_hs_cipher.decrypt(raw, hdr2)
        if inner_ct == CONTENT_ALERT:
            return None, None
        if inner_ct != CONTENT_HANDSHAKE:
            return None, None

        transcript_for_client_fin = transcript_before_fin + fin_msg
        c_fin_key = _hkdf_expand_label(c_hs_secret, b"finished", b"", 32)
        expected = hmac.new(c_fin_key, hashlib.sha256(transcript_for_client_fin).digest(), hashlib.sha256).digest()
        if inner_pt[0] != HS_FINISHED or not hmac.compare_digest(inner_pt[4:36], expected):
            return None, None

        # --- Application secrets ---
        full_hash = hashlib.sha256(transcript_for_client_fin).digest()
        derived2 = _hkdf_expand_label(handshake_secret, b"derived", empty_hash, 32)
        master_secret = _hkdf_extract(derived2, b"\x00" * 32)

        c_ap_secret = _hkdf_expand_label(master_secret, b"c ap traffic", full_hash, 32)
        s_ap_secret = _hkdf_expand_label(master_secret, b"s ap traffic", full_hash, 32)

        c_ap_key = _hkdf_expand_label(c_ap_secret, b"key", b"", 16)
        c_ap_iv = _hkdf_expand_label(c_ap_secret, b"iv", b"", 12)
        s_ap_key = _hkdf_expand_label(s_ap_secret, b"key", b"", 16)
        s_ap_iv = _hkdf_expand_label(s_ap_secret, b"iv", b"", 12)

        client_app = _RecordCipher(c_ap_key, c_ap_iv)
        server_app = _RecordCipher(s_ap_key, s_ap_iv)

        log.info("[sslfork] handshake ok")

        client_reader, client_writer = _make_secure_streams(
            reader, writer, client_app, server_app
        )

        return client_reader, client_writer

    except Exception as e:
        log.error(f"[sslfork] handshake failed: {type(e).__name__}: {e}")
        return None, None


# ---------- Secure stream wrappers ----------

class _SecureReader:
    def __init__(self, raw_reader, cipher):
        self.raw = raw_reader
        self.cipher = cipher
        self.buf = b""

    async def readexactly(self, n):
        while len(self.buf) < n:
            try:
                ctype, payload, hdr = await _read_tls_record(self.raw)
            except asyncio.IncompleteReadError as e:
                raise asyncio.IncompleteReadError(e.partial + self.buf, n)
            if ctype == CONTENT_ALERT:
                raise ConnectionResetError("TLS alert")
            if ctype != CONTENT_APPLICATION_DATA:
                continue
            inner_ct, pt = self.cipher.decrypt(payload, hdr)
            if inner_ct == CONTENT_ALERT:
                raise ConnectionResetError("TLS alert")
            if inner_ct == CONTENT_APPLICATION_DATA:
                self.buf += pt
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    async def read(self, n=65536):
        if self.buf:
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        try:
            ctype, payload, hdr = await _read_tls_record(self.raw)
        except asyncio.IncompleteReadError:
            return b""
        if ctype == CONTENT_ALERT:
            return b""
        if ctype != CONTENT_APPLICATION_DATA:
            return b""
        inner_ct, pt = self.cipher.decrypt(payload, hdr)
        if inner_ct == CONTENT_ALERT:
            return b""
        return pt


class _SecureWriter:
    def __init__(self, raw_writer, cipher):
        self.raw = raw_writer
        self.cipher = cipher

    def write(self, data):
        self.raw.write(self.cipher.encrypt(CONTENT_APPLICATION_DATA, data))

    async def drain(self):
        await self.raw.drain()

    def close(self):
        self.raw.close()

    async def wait_closed(self):
        await self.raw.wait_closed()

    def get_extra_info(self, name, default=None):
        return self.raw.get_extra_info(name, default)


def _make_secure_streams(raw_reader, raw_writer, client_cipher, server_cipher):
    return (
        _SecureReader(raw_reader, client_cipher),
        _SecureWriter(raw_writer, server_cipher),
    )