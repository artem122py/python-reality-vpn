# Changelog

Все значимые изменения в проекте.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).

## [2.1.0] — 2026-09-26

**XTLS-Vision, XUDP, SNI-routing, чистые логи.**

### Added
- **XTLS-Vision** — padding-обфускация для TLS-in-TLS
  - Protobuf-парсер VLESS Addons (`_parse_vless_addons`)
  - Vision включается **до** VLESS-ответа
- **XUDP (UDP over Mux)** — `cmd=0x03` с Vision-конвертом
  - Парсинг XUDP-фреймов (New/Keep)
  - UDP-релей через `_handle_udp`
  - Fallback на legacy VLESS UDP `[len(2)][payload]`
- **setup.sh** — автоустановка для Termux / Debian / Ubuntu / RPi
- **FAQ** в README (RU + EN)

### Changed
- Версия **2.1.0**
- Все диагностические логи → `log.debug`
- Канонический `config.json` (убраны `vision_*_padding_*`, `vision_debug`, `reality_enabled`)
- `qrcode` → опциональная зависимость
- Docker compose: `server.log` вместо `vpn.log`
- README переписан, добавлены XUDP, Vision, SNI-routing, FAQ

### Removed
- `release.sh` (жёстко привязан к Termux)
- `server.log` из git
- `tests/` в корне (дубликат `src/reality_vpn/tests/`)
- Неиспользуемые импорты (`hashlib`, `hmac`, `defaultdict`, `time`, `os`, `tempfile`, `pytest`, `sys`)
- Неиспользуемая функция `resolve_dest` в `sni_routing.py`
- BETA-предупреждения из кода и README

### Fixed
- `enable_vision_after_header` вызывается **до** VLESS-ответа
- `_SecureReader.buf` корректно читается для leftover
- Паддинг VLESS-ответа больше не обнуляется
- Тесты обновлены под 6-tuple `_read_vless_header`

---

## [2.0.0] — 2026-09-25

**Большой релиз: новая структура пакета, SNI-routing, улучшенный UDP.**

### Added
- **SNI-routing** — разные `dest` для разных SNI
  - `sni_routes` в конфиге: `{"sni": "host:port"}`
  - Поддержка wildcard: `*.example.com`
  - Fallback на `dest` для неизвестных SNI
- **Traffic limits** per user
  - `traffic_limits_enabled` (по умолчанию `false`)
  - `limit_bytes` на пользователя
  - Команда `reality-vpn traffic`
- **UDP-relay** — переписан
  - Два таска (c2u, u2c) с корректной остановкой
  - Раздельные таймауты (idle + payload)
  - Счётчики пакетов/байт в лог
- **CLI-команды**:
  - `reality-vpn version`
  - `reality-vpn traffic`
  - `reality-vpn users usage`
- **TCP keepalive** + **TCP_NODELAY** на исходящих соединениях
- **SIGPIPE handling** — сервер не падает при write в закрытый сокет
- **Ограничение буфера** в `_SecureReader` (1 MB)
- **`errors` counter** в статистике
- **Версия сервера** печатается при старте

### Changed
- **Структура проекта**: `src/reality_vpn/` с подпакетами:
  - `core/` — TLS 1.3, Reality, SNI-routing
  - `server/` — VLESS-сервер, UDP, Vision
  - `cli/` — main, commands, config
  - `utils/` — log, stats, guard, traffic, linkgen, genconf
  - `tests/` — все тесты
- **Установка как пакет**: `pip install -e .`
- **Точка входа**: `reality-vpn` (консольная команда)
- **Запуск через `python -m reality_vpn`**
- **`main.py`** в корне — обёртка для обратной совместимости
- **Docker/deploy** — в `deploy/`
- **Примеры** — в `examples/`

### Fixed
- Убран dummy `NewSessionTicket` — ломал Happ
- Исправлены все импорты после рефакторинга
- `cmd_version` и `cmd_traffic` правильно зарегистрированы в CLI

### Removed
- `testClientTLS.py` — устаревший, несовместим с текущим Reality
- `sni_routing.py` в корне (перемещён в `core/`)

---

## [1.0.0] — 2026-09-25

Первый публичный релиз.

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
