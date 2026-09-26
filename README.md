# Python Reality VPN

[![Tests](https://github.com/artem122py/python-reality-vpn/actions/workflows/test.yml/badge.svg)](https://github.com/artem122py/python-reality-vpn/actions/workflows/test.yml)
[![Version](https://img.shields.io/badge/version-2.1.0-blue)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20RPi-orange)]()

[English version](./README_ENG.md) | Русская версия

Собственный VPN-сервер с **Xray-совместимым REALITY** на чистом Python.
Написан с нуля: свой TLS 1.3, своя реализация Reality, свой VLESS, своя поддержка XTLS-Vision.

Работает с настоящими Xray-клиентами: **Happ**, **NekoBox**, **v2rayNG**.

---

## Возможности

- **TLS 1.3 с нуля** — handshake, key schedule, AEAD (X25519 + HKDF-SHA256 + AES-128-GCM)
- **REALITY** — маскировка под `ya.ru` (или другой сайт), устойчива к активному зондированию
- **VLESS** — TCP + UDP релей
- **XTLS-Vision** — padding для обфускации TLS-in-TLS
- **XUDP** — UDP-over-Mux для Xray-клиентов
- **SNI-routing** — разные `dest` для разных SNI
- **Anti-replay** — защита от повторов `session_id`
- **Rate limiting** — бан IP после N попыток
- **Мультиюзер** — несколько UUID и `short_id`
- **Лимиты трафика** — per-user (отключено по умолчанию)
- **Статистика** — uptime, соединения, трафик
- **Логи с уровнями** — DEBUG/INFO/WARN/ERROR, ротация в файл
- **Генератор ссылок** — `vless://` + QR-код
- **CLI** — `status`, `stop`, `users`, `link`, `stats`, `traffic`, `version`
- **Graceful shutdown** — корректное завершение по SIGINT/SIGTERM

---

## Быстрый старт

### Зависимости

    pip install cryptography kyber-py
    # опционально, для QR-кода:
    pip install qrcode

Требуется **Python 3.10+**.

### Установка

    # Автоматически (рекомендуется):
    bash setup.sh

    # Вручную:
    git clone https://github.com/artem122py/python-reality-vpn.git
    cd python-reality-vpn
    pip install -e .

### Запуск

    # Первый запуск — сгенерирует config.json:
    python -m reality_vpn server noconfig 0.0.0.0

    # Обычный запуск:
    python -m reality_vpn server 0.0.0.0

    # Или через консольную команду (после pip install -e .):
    reality-vpn server 0.0.0.0

В логе появится ссылка `vless://...` — импортируй её в Happ / NekoBox / v2rayNG.

### CLI

    reality-vpn status                    # работает ли сервер
    reality-vpn stop                      # остановить
    reality-vpn users list                # список пользователей
    reality-vpn users add friend          # добавить друга
    reality-vpn users remove <uuid>       # удалить
    reality-vpn link friend 1.2.3.4 443   # ссылка для юзера
    reality-vpn stats                     # статистика
    reality-vpn traffic                   # использование трафика
    reality-vpn version                   # версия сервера

---

## Структура

    python-reality-vpn/
    ├── src/reality_vpn/
    │   ├── core/
    │   │   ├── reality.py        — Reality-auth + anti-replay
    │   │   ├── sni_routing.py    — SNI → dest роутинг
    │   │   └── tls13.py          — TLS 1.3 + REALITY handshake
    │   ├── server/
    │   │   ├── server.py         — VLESS TCP/UDP сервер
    │   │   └── vision.py         — XTLS-Vision padding
    │   ├── cli/
    │   │   ├── main.py           — точка входа CLI
    │   │   ├── commands.py       — команды (status/stop/users/...)
    │   │   └── config.py         — обёртка над config.json
    │   ├── utils/
    │   │   ├── genconf.py        — генерация конфига
    │   │   ├── linkgen.py        — генератор vless://
    │   │   ├── log.py            — логирование
    │   │   ├── stats.py          — счётчики
    │   │   ├── guard.py          — rate limiting
    │   │   └── traffic.py        — лимиты трафика
    │   └── tests/                — pytest-тесты
    ├── deploy/                   — Docker / docker-compose
    ├── examples/testClient.py    — тестовый VLESS-клиент
    ├── setup.sh                  — автоустановка
    ├── pyproject.toml
    └── config.example.json

---

## Как работает REALITY

Xray REALITY маскирует VPN под обычный HTTPS-сайт.

### 1. session_id как скрытый канал

Клиент шифрует туда версию / timestamp / short_id:

    plaintext = [version(3)] [reserved(1)] [timestamp(4)] [short_id(8)]
    key       = HKDF(X25519_static_shared, salt=client_random[:20], info="REALITY")
    nonce     = client_random[20:32]
    AAD       = ClientHello с занулённым session_id

### 2. HMAC-подпись сертификата

Вместо стандартной криптографической подписи:

    signature = HMAC-SHA512(AuthKey, ed25519_public_key)

AuthKey выводится из X25519 static private key и публичного ключа клиента. Легитимный клиент проверяет HMAC — CA не нужен.

### 3. Fallback

Для чужих клиентов (сканеры, DPI-зонды, браузеры) сервер **прозрачно проксирует TCP** на `dest` (например, `ya.ru:443`). Сканер видит настоящий сертификат Яндекса и не может отличить VPN от обычного сайта.

Подробнее — в `src/reality_vpn/core/tls13.py` и `src/reality_vpn/core/reality.py`.

---

## XTLS-Vision

Vision — это padding-обфускация, которая маскирует TLS-in-TLS: клиент (Happ и др.) и сервер добавляют случайный padding к первым пакетам после VLESS-заголовка, чтобы у DPI не было характерного паттерна.

Включается флагом `use_vision: true` в конфиге. Работает **только по TCP** (UDP через Vision идёт отдельным путём — см. XUDP).

В логе появится дополнительная ссылка:

    VLESS Link (no vision): vless://...
    VLESS Link (vision):    vless://...&flow=xtls-rprx-vision#vpn-vision

Импортируй **vision-ссылку** в Happ, если хочешь обфускацию.

---

## XUDP (UDP over Mux)

Happ / Xray-клиенты могут передавать UDP через VLESS-канал в формате XUDP (`cmd=0x03`, Mux.Cool). Сервер поддерживает это: UDP-фреймы принимаются, парсятся, проксируются через UDP-сокет, ответ упаковывается обратно.

**Важно:** в РФ провайдеры часто режут UDP/53, поэтому для DNS рекомендуется DoH (`https://dns.google/dns-query`) в настройках Happ — это обходит проблему полностью.

---

## Конфигурация

`config.json` (генерируется автоматически, **не коммитится**):

| Поле | Описание | Default |
|------|----------|---------|
| `uuid` | UUID клиента | auto |
| `private_key` / `public_key` | X25519 ключи (hex) | auto |
| `short_id` | 8 байт в hex | auto |
| `dest` | сайт-маскировка | `ya.ru:443` |
| `listen_port` | порт | `8443` |
| `security` | `reality` / `tls` / `none` | `reality` |
| `use_vision` | включить XTLS-Vision | `false` |
| `sni_routes` | `{sni: "host:port"}` для SNI-роутинга | `{}` |
| `debug` | подробные логи | `false` |
| `log_file` | путь для логов (пусто = только консоль) | `""` |
| `stats_interval` | интервал stats в секундах | `60` |
| `replay_ttl` | окно anti-replay | `300` |
| `clienthello_timeout` | таймаут ClientHello | `5` |
| `handshake_timeout` | таймаут handshake | `10` |
| `idle_timeout` | простой соединения | `300` |
| `maxTimeDiff` | максимальное расхождение timestamp | `120` |
| `traffic_limits_enabled` | включить лимиты | `false` |
| `traffic_limit_default` | лимит по умолчанию (байт) | `0` |
| `users` | список `{name, uuid, short_id, limit_bytes}` | `[]` |

---

## Развёртывание на VPS / Raspberry Pi

### Автоматический скрипт

    sudo ./setup.sh

Скрипт определит окружение (Termux / Debian / Ubuntu / RPi), установит зависимости, сгенерирует конфиг и опционально настроит systemd-сервис.

### Вручную

    python3 -m venv ~/vpn-env
    source ~/vpn-env/bin/activate
    pip install cryptography kyber-py
    pip install -e .
    python -m reality_vpn server 0.0.0.0

### Systemd

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

## Безопасность

- **Не выкладывай ссылку публично.** UUID в ссылке = пароль.
- **Не давай доступ третьим лицам.** Это нарушает ст. 13.32 КоАП РФ.
- **Reality на Python уязвим к новым версиям Xray.** Если Xray изменит формат `session_id` — сервер сломается.
- **Своя криптография — риск.** Мы используем проверенные примитивы (`cryptography`), но структура handshake написана самостоятельно. Для критичных задач — используй оригинальный `Xray-core`.

---

## Что проверено

- Happ (Android) — Reality, Vision
- NekoBox (Android)
- v2rayNG (Android)
- Termux (Android)
- Debian / Ubuntu (VPS)
- Raspberry Pi 5

---

## FAQ

**Q: Happ показывает "TLS Handshake Error".**
A: Скорее всего, не резолвится DNS. Включи DoH в Happ: Settings → DNS → `https://dns.google/dns-query`.

**Q: Telegram / YouTube не работают через VPN.**
A: Если сервер в РФ, он сам под РКН. Решение — VPS вне РФ.

**Q: Как проверить, что сервер работает?**
A: `reality-vpn status` — покажет, слушает ли порт. Или открой `https://ya.ru` через VPN — должен открыться.

**Q: `python -m reality_vpn server` не запускается.**
A: Проверь `pip install -e .` и `python -c "import reality_vpn; print(reality_vpn.__version__)"`.

---

## Лицензия

MIT — используй, форкай, улучшай.

---

## Roadmap

- [x] XTLS-Vision (padding)
- [x] XUDP (UDP over Mux)
- [x] SNI-routing
- [ ] Мобильное приложение-обёртка
- [ ] Полная поддержка AmneziaWG для UDP

---

Написано как исследование протокола REALITY.
Не заменяет Xray-core, но показывает, что реализация на Python возможна.
