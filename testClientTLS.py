# testClientTLS.py
import asyncio
import struct
import hashlib
import hmac
import os
import json
import socket
import uuid as uuidlib
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography import x509


# ---------- TLS constants ----------

CONTENT_CHANGE_CIPHER_SPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17

HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_FINISHED = 0x14

GROUP_X25519 = 0x001d
CIPHER_AES_128_GCM_SHA256 = 0x1301
SIG_RSA_PSS_RSAE_SHA256 = 0x0804

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_SUPPORTED_VERSIONS = 0x002b
EXT_KEY_SHARE = 0x0033


# ---------- TLS record layer ----------

async def _read_tls_record(reader):
    hdr = await reader.readexactly(5)
    ctype = hdr[0]
    length = struct.unpack(">H", hdr[3:5])[0]
    payload = await reader.readexactly(length)
    return ctype, payload, hdr


def _pack_tls_record(ctype, payload):
    return bytes([ctype]) + struct.pack(">HH", 0x0303, len(payload)) + payload


# ---------- HKDF ----------

def _hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret, label, context, length):
    full_label = b"tls13 " + label
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label)
    return hkdf.derive(secret)


# ---------- AEAD record cipher ----------

class _RecordCipher:
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


# ---------- ClientHello builder ----------

def build_client_hello(sni: str, session_id: bytes, client_pub: bytes) -> bytes:
    body = bytearray()
    body += struct.pack(">H", 0x0303)          # legacy_version
    body += os.urandom(32)                      # random
    body += bytes([len(session_id)]) + session_id
    # cipher_suites
    cs = struct.pack(">H", CIPHER_AES_128_GCM_SHA256)
    body += struct.pack(">H", len(cs)) + cs
    # compression
    body += b"\x01\x00"

    exts = bytearray()

    # server_name
    sni_b = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    exts += struct.pack(">HH", EXT_SERVER_NAME, len(sni_list)) + sni_list

    # supported_groups
    groups = struct.pack(">HH", 2, GROUP_X25519)
    exts += struct.pack(">HH", EXT_SUPPORTED_GROUPS, len(groups)) + groups

    # signature_algorithms
    sigalgs = struct.pack(">HH", 2, SIG_RSA_PSS_RSAE_SHA256)
    exts += struct.pack(">HH", EXT_SIGNATURE_ALGORITHMS, len(sigalgs)) + sigalgs

    # supported_versions
    sv = b"\x02" + struct.pack(">H", 0x0304)
    exts += struct.pack(">HH", EXT_SUPPORTED_VERSIONS, len(sv)) + sv

    # key_share
    ks_entry = struct.pack(">HH", GROUP_X25519, len(client_pub)) + client_pub
    ks_list = struct.pack(">H", len(ks_entry)) + ks_entry
    exts += struct.pack(">HH", EXT_KEY_SHARE, len(ks_list)) + ks_list

    body += struct.pack(">H", len(exts)) + exts

    return bytes([HS_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + bytes(body)


# ---------- ServerHello parser ----------

def parse_server_hello(payload: bytes) -> dict:
    assert payload[0] == HS_SERVER_HELLO
    body = payload[4:]

    server_random = body[2:34]
    pos = 34
    sid_len = body[pos]
    session_id = body[pos + 1: pos + 1 + sid_len]
    pos += 1 + sid_len
    cipher_suite = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    pos += 1  # compression

    ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_len

    server_pub = None
    supported_versions = []
    while pos < ext_end:
        etype = struct.unpack(">H", body[pos:pos + 2])[0]
        elen = struct.unpack(">H", body[pos + 2:pos + 4])[0]
        edata = body[pos + 4:pos + 4 + elen]
        pos += 4 + elen

        if etype == EXT_KEY_SHARE:
            group = struct.unpack(">H", edata[0:2])[0]
            klen = struct.unpack(">H", edata[2:4])[0]
            if group == GROUP_X25519:
                server_pub = edata[4:4 + klen]
        elif etype == EXT_SUPPORTED_VERSIONS:
            supported_versions.append(struct.unpack(">H", edata[0:2])[0])

    return {
        "server_random": server_random,
        "session_id": session_id,
        "cipher_suite": cipher_suite,
        "server_pub": server_pub,
        "supported_versions": supported_versions,
    }


# ---------- client handshake ----------

async def client_handshake(reader, writer, sni: str,
                            server_pub_bytes: bytes, short_id: bytes):
    # 1. X25519
    client_priv = X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Reality auth: shared = X25519(client_priv, server_pub)
    #               auth = HMAC-SHA256(shared, short_id)
    server_pub_obj = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = client_priv.exchange(server_pub_obj)
    auth_tag = hmac.new(shared, short_id, hashlib.sha256).digest()
    session_id = auth_tag  # 32 байта

    # 2. ClientHello
    ch_msg = build_client_hello(sni, session_id, client_pub)
    print(f"[cli] ClientHello {len(ch_msg)}B, session_id={session_id.hex()}")
    writer.write(_pack_tls_record(CONTENT_HANDSHAKE, ch_msg))
    await writer.drain()

    # 3. ServerHello
    ctype, sh_payload, _ = await _read_tls_record(reader)
    if ctype != CONTENT_HANDSHAKE:
        raise ConnectionError(f"expected ServerHello, got 0x{ctype:02x}")
    sh = parse_server_hello(sh_payload)
    if sh["server_pub"] is None:
        raise ConnectionError("no X25519 in ServerHello")
    print(f"[cli] ServerHello cipher=0x{sh['cipher_suite']:04x}")

    # 4. shared secret
    server_pub = X25519PublicKey.from_public_bytes(sh["server_pub"])
    shared = client_priv.exchange(server_pub)

    # 5. Key schedule
    empty_hash = hashlib.sha256(b"").digest()
    early_secret = _hkdf_extract(b"\x00" * 32, b"\x00" * 32)
    derived = _hkdf_expand_label(early_secret, b"derived", empty_hash, 32)
    handshake_secret = _hkdf_extract(derived, shared)

    transcript_ch_sh = ch_msg + sh_payload
    chs_hash = hashlib.sha256(transcript_ch_sh).digest()

    c_hs_secret = _hkdf_expand_label(handshake_secret, b"c hs traffic", chs_hash, 32)
    s_hs_secret = _hkdf_expand_label(handshake_secret, b"s hs traffic", chs_hash, 32)

    c_hs_key = _hkdf_expand_label(c_hs_secret, b"key", b"", 16)
    c_hs_iv = _hkdf_expand_label(c_hs_secret, b"iv", b"", 12)
    s_hs_key = _hkdf_expand_label(s_hs_secret, b"key", b"", 16)
    s_hs_iv = _hkdf_expand_label(s_hs_secret, b"iv", b"", 12)

    client_hs_cipher = _RecordCipher(c_hs_key, c_hs_iv)
    server_hs_cipher = _RecordCipher(s_hs_key, s_hs_iv)

    # 6. ChangeCipherSpec (dummy)
    writer.write(b"\x14\x03\x03\x00\x01\x01")
    await writer.drain()

    # 7. Читаем зашифрованные сообщения сервера
    ctype, raw, hdr = await _read_tls_record(reader)
    if ctype != CONTENT_APPLICATION_DATA:
        raise ConnectionError(f"expected encrypted, got 0x{ctype:02x}")

    inner_ct, inner_pt = server_hs_cipher.decrypt(raw, hdr)
    if inner_ct != CONTENT_HANDSHAKE:
        raise ConnectionError(f"inner not handshake: 0x{inner_ct:02x}")

    # разбиваем на отдельные handshake-сообщения
    msgs = []
    p = 0
    while p < len(inner_pt):
        mt = inner_pt[p]
        mlen = int.from_bytes(inner_pt[p + 1:p + 4], "big")
        full = inner_pt[p:p + 4 + mlen]
        msgs.append((mt, full[4:], full))
        p += 4 + mlen

    print(f"[cli] got {len(msgs)} msgs: {[hex(m[0]) for m in msgs]}")

    # ---- Reality cert verification ----
    cert_msg_body = None
    for mt, body, full in msgs:
        if mt == 0x0b:  # Certificate
            cert_msg_body = body
            break
    if cert_msg_body is None:
        raise ConnectionError("no Certificate in server handshake")

    p = 0
    ctx_len = cert_msg_body[p]
    p += 1 + ctx_len
    p += 3  # list length (не нужно)
    cert_len = int.from_bytes(cert_msg_body[p:p+3], "big")
    p += 3
    cert_der = cert_msg_body[p:p+cert_len]

    cert = x509.load_der_x509_certificate(cert_der)
    cert_pub = cert.public_key()
    actual_pub_bytes = cert_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    cert_seed = _hkdf_expand_label(shared, b"reality-cert", b"", 32)
    expected_pub = Ed25519PrivateKey.from_private_bytes(cert_seed).public_key()
    expected_pub_bytes = expected_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if actual_pub_bytes != expected_pub_bytes:
        raise ConnectionError(
            f"server cert pub key mismatch: "
            f"{actual_pub_bytes.hex()[:16]} != {expected_pub_bytes.hex()[:16]}"
        )
    print("[cli] server cert pub key matches derived from shared (Reality OK)")

    if not msgs or msgs[-1][0] != HS_FINISHED:
        raise ConnectionError("no Finished at the end")

    # Транскрипт для проверки server Finished: CH+SH + всё кроме Fin
    transcript_for_server_fin = transcript_ch_sh
    for _, _, full in msgs[:-1]:
        transcript_for_server_fin += full

    s_fin_key = _hkdf_expand_label(s_hs_secret, b"finished", b"", 32)
    expected = hmac.new(
        s_fin_key,
        hashlib.sha256(transcript_for_server_fin).digest(),
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(msgs[-1][1], expected):
        raise ConnectionError("server Finished mismatch")
    print("[cli] server Finished verified")

    # 8. Свой Finished
    transcript_before_client_fin = transcript_for_server_fin + msgs[-1][2]
    c_fin_key = _hkdf_expand_label(c_hs_secret, b"finished", b"", 32)
    c_fin_verify = hmac.new(
        c_fin_key,
        hashlib.sha256(transcript_before_client_fin).digest(),
        hashlib.sha256,
    ).digest()
    c_fin_msg = bytes([HS_FINISHED]) + len(c_fin_verify).to_bytes(3, "big") + c_fin_verify

    writer.write(client_hs_cipher.encrypt(CONTENT_HANDSHAKE, c_fin_msg))
    await writer.drain()
    print("[cli] sent Finished")

    # 9. Application secrets
    full_hash = hashlib.sha256(transcript_before_client_fin).digest()
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

    # Читаем server_app, пишем client_app
    return _make_secure_streams(reader, writer, server_app, client_app)


# ---------- secure streams ----------

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


def _make_secure_streams(raw_reader, raw_writer, read_cipher, write_cipher):
    return (
        _SecureReader(raw_reader, read_cipher),
        _SecureWriter(raw_writer, write_cipher),
    )


# ---------- VLESS ----------

def load_cfg():
    with open("config.json") as f:
        return json.load(f)


def build_vless_header(uuid_str, host, port):
    out = bytearray()
    out.append(0x00)
    out += uuidlib.UUID(uuid_str).bytes
    out.append(0x00)                 # opt_len
    out.append(0x01)                 # cmd TCP
    out += struct.pack(">H", port)
    try:
        socket.inet_aton(host)
        out.append(0x01)
        out += socket.inet_aton(host)
    except OSError:
        out.append(0x02)
        hb = host.encode("idna")
        out.append(len(hb))
        out += hb
    return bytes(out)


# ---------- run ----------

async def run(server_host, server_port, sni, target_host, target_port, request):
    cfg = load_cfg()
    uuid_str = cfg["uuid"]
    short_id = bytes.fromhex(cfg["short_id"])
    server_pub_bytes = bytes.fromhex(cfg["public_key"])

    print(f"[cli] TCP connect to {server_host}:{server_port}")
    reader, writer = await asyncio.open_connection(server_host, server_port)

    sec_reader, sec_writer = await client_handshake(
        reader, writer, sni, server_pub_bytes, short_id,
    )
    print("[cli] TLS handshake done")

    hdr = build_vless_header(uuid_str, target_host, target_port)
    print(f"[cli] VLESS header: {hdr.hex()}")
    sec_writer.write(hdr)
    await sec_writer.drain()

    resp = await sec_reader.readexactly(2)
    if resp != b"\x00\x00":
        print(f"[!] bad VLESS response: {resp.hex()}")
        writer.close()
        return
    print("[cli] VLESS accepted")

    sec_writer.write(request)
    await sec_writer.drain()

    print("[cli] response:")
    print("-" * 60)
    total = 0
    while True:
        data = await sec_reader.read(4096)
        if not data:
            break
        total += len(data)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    print()
    print("-" * 60)
    print(f"[cli] received {total} bytes")

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


def main():
    server_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443

    sni = "localhost"

    target_host = "example.com"
    target_port = 80
    request = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"

    asyncio.run(run(server_host, server_port, sni,
                    target_host, target_port, request))


if __name__ == "__main__":
    main()