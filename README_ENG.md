# Python Reality VPN

[![Tests](https://github.com/artem122py/python-reality-vpn/actions/workflows/test.yml/badge.svg)](https://github.com/artem122py/python-reality-vpn/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20RPi-orange)]()

A custom VPN server with **Xray-compatible REALITY**, written in pure Python.
Built from scratch: our own TLS 1.3, our own Reality implementation, our own VLESS.

Works with real Xray clients: **Happ**, **NekoBox**, **v2rayNG**.

---

## Features

- **TLS 1.3 from scratch** — custom handshake, key schedule, AEAD (X25519 + HKDF-SHA256 + AES-128-GCM)
- **REALITY** — masquerades as `ya.ru` (or any other site), resistant to active probing
- **VLESS** — TCP + UDP relay
- **Anti-replay** — protection against session_id replay attacks
- **Rate limiting** — IP ban after N failed attempts
- **Multi-user** — multiple UUIDs and short_ids
- **Statistics** — uptime, connections, traffic counters
- **Structured logging** — DEBUG/INFO/WARN/ERROR with file rotation
- **Link generator** — `vless://` URLs with QR codes
- **CLI** — `status`, `stop`, `users add/remove/list`, `link`
- **Graceful shutdown** — clean exit on SIGINT/SIGTERM

---

## Quick Start

### Dependencies

    pip install cryptography kyber-py
    # optional, for QR codes:
    pip install qrcode

Requires **Python 3.10+**.
If your `cryptography` build lacks ML-KEM, install `kyber-py` as a fallback.

### Run

    # Generate config on first run
    python main.py server noconfig 0.0.0.0

    # Normal start
    python main.py server 0.0.0.0

The log will show a `vless://...` link.
Import it into Happ, NekoBox, or v2rayNG.

### CLI

    python main.py status                        # is server running
    python main.py stop                          # stop server
    python main.py users list                    # list users
    python main.py users add friend              # add a user
    python main.py users remove <uuid>           # remove user
    python main.py link friend 1.2.3.4 443       # link for specific user
    python linkgen.py 1.2.3.4 443 friend --qr    # link + QR code

---

## Project Structure

    VPN/
    ├── main.py             — CLI and entry point
    ├── genconf.py          — config generation
    ├── vpnconfig.py        — config.json wrapper
    ├── vpnlog.py           — logging (levels, rotation)
    ├── vpnstats.py         — counters
    ├── vpnguard.py         — rate limiting
    ├── vpncli.py           — CLI commands
    ├── server.py           — VLESS TCP/UDP server
    ├── sslfork.py          — TLS 1.3 + REALITY
    ├── reality_pq.py       — Reality-auth + anti-replay
    ├── linkgen.py          — vless:// link generator
    ├── testClient.py       — VLESS test client
    ├── testClientTLS.py    — TLS 1.3 test client
    └── config.example.json

---

## How REALITY Works

Xray REALITY disguises a VPN as ordinary HTTPS traffic to a legitimate website.

### 1. session_id as a covert channel

The client embeds authentication data into the TLS `session_id` field (32 bytes),
which is normally ignored in TLS 1.3:

    plaintext = [version(3)] [reserved(1)] [timestamp(4)] [short_id(8)]
    key       = HKDF(X25519_static_shared, salt=client_random[:20], info="REALITY")
    nonce     = client_random[20:32]
    AAD       = ClientHello with session_id zeroed out

### 2. HMAC-signed certificate

Instead of a standard cryptographic signature, REALITY uses:

    signature = HMAC-SHA512(AuthKey, ed25519_public_key)

`AuthKey` is derived from the X25519 static private key and the client's public key.
A legitimate client verifies this HMAC to authenticate the server — no CA needed.

### 3. Fallback

For unknown clients (scanners, DPI probes, browsers), the server transparently
proxies the TCP stream to `dest` (e.g., `ya.ru:443`). An outside observer sees
a real certificate from Yandex and cannot distinguish the VPN server from a normal site.

Details in `sslfork.py` and `reality_pq.py`.

---

## Configuration

`config.json` (generated automatically, **not committed**):

| Field | Description | Default |
|-------|-------------|---------|
| `uuid` | Client UUID | auto |
| `private_key` / `public_key` | X25519 keys (hex) | auto |
| `short_id` | 8 bytes in hex | auto |
| `dest` | Cover site | `ya.ru:443` |
| `listen_port` | Port | `8443` |
| `security` | `reality` / `tls` / `none` | `reality` |
| `debug` | Verbose logging | `false` |
| `log_file` | Log path (empty = console only) | `""` |
| `stats_interval` | Stats output every N seconds | `60` |
| `replay_ttl` | Anti-replay window | `300` |
| `clienthello_timeout` | ClientHello timeout | `5` |
| `handshake_timeout` | Full handshake timeout | `10` |
| `idle_timeout` | Idle connection timeout | `300` |

---

## Deployment on VPS / Raspberry Pi

### Automated script

    sudo ./setup.sh

Installs Python, creates a venv, sets up systemd, generates config.

### Manual

    python3 -m venv ~/vpn-env
    source ~/vpn-env/bin/activate
    pip install cryptography kyber-py
    python main.py server 0.0.0.0

### Systemd service

    [Unit]
    Description=Python Reality VPN
    After=network.target

    [Service]
    Type=simple
    User=pi
    WorkingDirectory=/home/pi/VPN
    ExecStart=/home/pi/vpn-env/bin/python /home/pi/VPN/main.py server 0.0.0.0
    Restart=always

    [Install]
    WantedBy=multi-user.target

---

## Security

- **Do not publish your `vless://` link.** The UUID is the password.
- **Do not share access with third parties.** In Russia, this violates Article 13.32 of the Administrative Code.
- **Python REALITY is fragile against new Xray versions.** If Xray changes the `session_id` format, this server will break.
- **Custom crypto is risky.** We use audited primitives (`cryptography`), but the handshake structure is written by hand. For critical use cases, prefer the original `Xray-core`.

---

## Tested with

- Happ (Android)
- NekoBox (Android)
- v2rayNG (Android)
- Termux (Android)
- Debian / Ubuntu (VPS)
- Raspberry Pi 5

---

## License

MIT — free to use, fork, and modify.

---

## Roadmap

- XTLS-Vision (padding for better obfuscation)
- Multiple `dest` targets (SNI routing)
- Mobile wrapper app

---

Written as an exploration of the REALITY protocol.
Not a replacement for Xray-core, but a demonstration that a pure-Python implementation is possible.
