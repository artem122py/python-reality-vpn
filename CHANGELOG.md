# Changelog

## [2.1.0] — 2026-09-26

**XUDP (Xray UDP over Mux) и очистка от отладочного кода.**

### Added
- **XUDP-обработчик** (`cmd=0x03`): теперь сервер принимает UDP-фреймы
  от Happ/XTLS-клиентов и проксирует их через UDP-сокет
  - Парсинг XUDP-фреймов (New/Keep) внутри Vision-конверта
  - Поддержка Keep-ответов (`Status=0x02`)
  - Поддержка Vision-Vision wrapper (`uuid + cmd + clen + plen`)
- **Автоопределение формата XUDP** (Keep без GlobalID)
- **`_handle_udp_legacy`** — старый VLESS UDP `[len(2)][payload]` как fallback

### Changed
- Все отладочные `log.info` / `log.warn` для Vision/XUDP/pipe понижены до `log.debug`
- Убраны диагностические hex-дампы (они включаются при `debug = true`)
- Версия поднята до 2.1.0

### Fixed
- `enable_vision_after_header` вызывается **до** VLESS-ответа (а не после)
- `_SecureReader.buf` корректно читается для leftover
- Паддинг VLESS-ответа больше не обнуляется
- `flow=xtls-rprx-vision` обрабатывается корректно (protobuf-парсер Addons)

Все значимые изменения в проекте.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).

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

### Migration from 1.0.x

**Новая структура**:
- Файлы теперь в `src/reality_vpn/`
- Импорты: `from server import` → `from reality_vpn.server.server import`
- Установка: `pip install -e .`

**Конфиг** (без изменений в API):
```json
{
  "dest": "ya.ru:443",
  "sni_routes": {
    "www.microsoft.com": "www.microsoft.com:443",
    "www.google.com": "www.google.com:443"
  },
  "traffic_limits_enabled": false
}
