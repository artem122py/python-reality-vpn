# Changelog

All notable changes to this project.

## [1.0.0] — 2026-09-25

First public release.

### Added
- TLS 1.3 server from scratch (X25519 + HKDF-SHA256 + AES-128-GCM)
- Xray-compatible REALITY (HMAC signature, session_id, fallback)
- VLESS TCP + UDP relay
- Anti-replay session_id cache
- Rate limiting with auto-ban
- Multi-user support
- Statistics (uptime, connections, traffic)
- Structured logging with rotation
- vless:// link generator + QR code
- CLI commands: status, stop, users, link
- Graceful shutdown
- Tests (pytest)
- GitHub Actions CI
- Docker support
- README in Russian and English

### Verified with
- Happ (Android)
- NekoBox (Android)
- v2rayNG (Android)
- Termux (Android)
- Debian/Ubuntu (VPS)
- Raspberry Pi 5
