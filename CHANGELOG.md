# Changelog

Все значимые изменения в проекте.

## [1.0.1] — 2026-09-25

### Added
- Traffic limits per user (disabled by default, `traffic_limits_enabled`)
- CLI commands: `traffic`, `users usage`, `version`
- TCP keepalive + TCP_NODELAY on outgoing connections
- SIGPIPE handling (no crash on write to closed socket)
- Buffer size limit in `_SecureReader` (1 MB, memory-exhaustion protection)
- `errors` counter in stats
- Version info on server startup

### Fixed
- Remove dummy NewSessionTicket (was breaking Happ)
- `cmd_version` and `cmd_traffic` correctly registered in CLI

### Removed
- `testClientTLS.py` (outdated, not compatible with current REALITY)

## [1.0.0] — 2026-09-25

Первый публичный релиз.

### Added
- TLS 1.3 сервер с нуля (X25519 + HKDF-SHA256 + AES-128-GCM)
- Xray-совместимый REALITY (HMAC-подпись, session_id, fallback)
- VLESS TCP + UDP релей
- Anti-replay кэш session_id
- Rate limiting с автобаном IP
- Мультиюзер (несколько UUID и short_id)
- Статистика (uptime, соединения, трафик)
- Модуль логирования с уровнями и ротацией
- Генератор `vless://` ссылок + QR-код
- CLI команды: `status`, `stop`, `users`, `link`
- Graceful shutdown (SIGINT/SIGTERM)
- Тесты (pytest)
- GitHub Actions CI
- Docker поддержка
- README на русском и английском

### Verified
- Happ (Android)
- NekoBox (Android)
- v2rayNG (Android)
- Termux (Android)
- Debian/Ubuntu (VPS)
- Raspberry Pi 5
