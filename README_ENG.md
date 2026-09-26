# Python Reality VPN

[![Tests](https://github.com/artem122py/python-reality-vpn/actions/workflows/test.yml/badge.svg)](https://github.com/artem122py/python-reality-vpn/actions/workflows/test.yml)
[![Version](https://img.shields.io/badge/version-2.1.0-blue)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20RPi-orange)]()

English version | [Русская версия](./README.md)

A custom VPN server with **Xray-compatible REALITY**, written in pure Python.
Built from scratch: our own TLS 1.3, our own Reality implementation, our own VLESS, our own XTLS-Vision support.

Works with real Xray clients: **Happ**, **NekoBox**, **v2rayNG**.

---

## Features

- **TLS 1.3 from scratch** — handshake, key schedule, AEAD (X25519 + HKDF-SHA256 + AES-128-GCM)
- **REALITY** — masquerades as `ya.ru` (or any site), resistant to active probing
- **VLESS** — TCP + UDP relay
- **XTLS-Vision** — padding for TLS-in-TLS obfuscation
- **XUDP** — UDP-over-Mux for Xray clients
- **SNI routing** — per-SNI `dest` fallback
- **Anti-replay** — protection against `session_id` replay
- **Rate limiting** — IP ban after N failed attempts
- **Multi-user** — multiple UUIDs and `short_id`s
- **Traffic limits** — per-user (disabled by default)
- **Statistics** — uptime, connections, traffic
- **Structured logging** — DEBUG/INFO/WARN/ERROR, file rotation
- **Link generator** — `vless://` URLs + QR code
- **CLI** — `status`, `stop`, `users`, `link`, `stats`, `traffic`, `version`
- **Graceful shutdown** — clean exit on SIGINT/SIGTERM

---

## Quick Start

### Dependencies

    pip install cryptography kyber-py
    # optional, for QR codes:
    pip install qrcode

Requires **Python 3.10+**.

### Install

    # Automatic (recommended):
    bash setup.sh

    # Manual:
    git clone https://github.com/artem122py/python-reality-vpn.git
    cd python-reality-vpn
    pip install -e .

### Run

    # First run — generates config.json:
    python -m reality_vpn server noconfig 0.0.0.0

    # Normal start:
    python -m reality_vpn server 0.0.0.0

    # Or via console entry point (after pip install -e .):
    reality-vpn server 0.0.0.0

The log will show a `vless://...` link. Import it into Happ, NekoBox, or v2rayNG.

### CLI

    reality-vpn status                    # is the server running
    reality-vpn stop                      # stop the server
    reality-vpn users list                # list users
    reality-vpn users add friend          # add a user
    reality-vpn users remove <uuid>       # remove a user
    reality-vpn link friend 1.2.3.4 443   # link for specific user
    reality-vpn stats                     # statistics
    reality-vpn traffic                   # traffic usage
    reality-vpn version                   # server version

---

## Project Structure

    python-reality-vpn/
    ├── src/reality_vpn/
    │   ├── core/
    │   │   ├── reality.py        — Reality auth + anti-replay
    │   │   ├── sni_routing.py    — SNI → dest routing
    │   │   └── tls13.py          — TLS 1.3 + REALITY handshake
    │   ├── server/
    │   │   ├── server.py         — VLESS TCP/UDP server
    │   │   └── vision.py         — XTLS-Vision padding
    │   ├── cli/
    │   │   ├── main.py           — CLI entry point
    │   │   ├── commands.py       — commands (status/stop/users/...)
    │   │   └── config.py         — config.json wrapper
    │   ├── utils/
    │   │   ├── genconf.py        — config generation
    │   │   ├── linkgen.py        — vless:// link generator
    │   │   ├── log.py            — logging
    │   │   ├── stats.py          — counters
    │   │   ├── guard.py          — rate limiting
    │   │   └── traffic.py        — traffic limits
    │   └── tests/                — pytest tests
    ├── deploy/                   — Docker / docker-compose
    ├── examples/testClient.py    — test VLESS client
    ├── setup.sh                  — auto-installer
    ├── pyproject.toml
    └── config.example.json

---

## How REALITY Works

Xray REALITY disguises a VPN as ordinary HTTPS traffic to a legitimate website.

### 1. session_id as a covert channel

The client embeds version / timestamp / short_id into the TLS `session_id` field (32 bytes), which is normally ignored in TLS 1.3:

    plaintext = [version(3)] [reserved(1)] [timestamp(4)] [short_id(8)]
    key       = HKDF(X25519_static_shared, salt=client_random[:20], info="REALITY")
    nonce     = client_random[20:32]
    AAD       = ClientHello with session_id zeroed out

### 2. HMAC-signed certificate

Instead of a standard cryptographic signature, REALITY uses:

    signature = HMAC-SHA512(AuthKey, ed25519_public_key)

AuthKey is derived from the X25519 static private key and the client's public key. A legitimate client verifies this HMAC — no CA needed.

### 3. Fallback

For unknown clients (scanners, DPI probes, browsers) the server transparently proxies the TCP stream to `dest` (e.g., `ya.ru:443`). An outside observer sees a real certificate from Yandex and cannot distinguish the VPN server from a normal site.

Details in `src/reality_vpn/core/tls13.py` and `src/reality_vpn/core/reality.py`.

---

## XTLS-Vision

Vision is padding-based obfuscation that hides TLS-in-TLS: client (Happ etc.) and server add random padding to the first packets after the VLESS header, so DPI cannot match a fixed pattern.

Enabled via `use_vision: true` in config. Works **over TCP only** (UDP uses a separate path — see XUDP).

The log will show an extra link:

    VLESS Link (no vision): vless://...
    VLESS Link (vision):    vless://...&flow=xtls-rprx-vision#vpn-vision

Import the **vision link** into Happ for obfuscation.

---

## XUDP (UDP over Mux)

Happ / Xray clients may send UDP over the VLESS channel using XUDP format (`cmd=0x03`, Mux.Cool). The server supports this: UDP frames are parsed, proxied through a UDP socket, and responses are wrapped back.

**Note:** in Russia ISPs often drop UDP/53, so DoH (`https://dns.google/dns-query`) in Happ settings is recommended — this bypasses the problem entirely.

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
| `use_vision` | Enable XTLS-Vision | `false` |
| `sni_routes` | `{sni: "host:port"}` for SNI routing | `{}` |
| `debug` | Verbose logging | `false` |
| `log_file` | Log path (empty = console only) | `""` |
| `stats_interval` | Stats output every N seconds | `60` |
| `replay_ttl` | Anti-replay window | `300` |
| `clienthello_timeout` | ClientHello timeout | `5` |
| `handshake_timeout` | Full handshake timeout | `10` |
| `idle_timeout` | Idle connection timeout | `300` |
| `maxTimeDiff` | Max timestamp skew | `120` |
| `traffic_limits_enabled` | Enable per-user limits | `false` |
| `traffic_limit_default` | Default limit (bytes) | `0` |
| `users` | List of `{name, uuid, short_id, limit_bytes}` | `[]` |

---

## Deployment on VPS / Raspberry Pi

### Automated script

    sudo ./setup.sh

Detects environment (Termux / Debian / Ubuntu / RPi), installs dependencies, generates config, and optionally sets up a systemd service.

### Manual

    python3 -m venv ~/vpn-env
    source ~/vpn-env/bin/activate
    pip install cryptography kyber-py
    pip install -e .
    python -m reality_vpn server 0.0.0.0

### Systemd service

    [Unit]
    Description=Python Reality VPN
    After=network.target

    [Service]
    Type=simple
    User=pi
    WorkingDirectory=/home/pi/python-reality-vpn
    ExecStart=/home/pi/vpn-env/bin/python -m reality_vpn server 0.0.0.0
    Restart=always
    RestartSec=5

    [Install]
    WantedBy=multi-user.target

    sudo systemctl daemon-reload
    sudo systemctl enable --now reality-vpn
    sudo journalctl -u reality-vpn -f

### Docker

    cd deploy
    docker compose up -d

---

## Security

- **Do not publish your `vless://` link.** The UUID is the password.
- **Do not share access with third parties.** In Russia, this violates Article 13.32 of the Administrative Code.
- **Python REALITY is fragile against new Xray versions.** If Xray changes the `session_id` format, this server will break.
- **Custom crypto is risky.** We use audited primitives (`cryptography`), but the handshake structure is written by hand. For critical use cases, prefer the original `Xray-core`.

---

## Tested with

- Happ (Android) — Reality, Vision
- NekoBox (Android)
- v2rayNG (Android)
- Termux (Android)
- Debian / Ubuntu (VPS)
- Raspberry Pi 5

---

## FAQ

**Q: Happ shows "TLS Handshake Error".**
A: DNS is likely not resolving. Enable DoH in Happ: Settings → DNS → `https://dns.google/dns-query`.

**Q: Telegram / YouTube don't work through the VPN.**
A: If the server is in Russia, it's subject to RKN blocking itself. Solution — a VPS outside Russia.

**Q: How to check if the server is running?**
A: `reality-vpn status` — shows whether the port is busy. Or open `https://ya.ru` via VPN — it should load.

**Q: `python -m reality_vpn server` doesn't start.**
A: Check `pip install -e .` and `python -c "import reality_vpn; print(reality_vpn.__version__)"`.

---

## License

MIT — free to use, fork, and modify.

---

## Roadmap

- [x] XTLS-Vision (padding)
- [x] XUDP (UDP over Mux)
- [x] SNI routing
- [ ] Mobile wrapper app
- [ ] Full AmneziaWG support for UDP

---

Written as an exploration of the REALITY protocol.
Not a replacement for Xray-core, but a demonstration that a pure-Python implementation is possible.
