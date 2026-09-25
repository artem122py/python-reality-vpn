# Python Reality VPN

Собственный VPN-сервер с **Xray-совместимым REALITY** на чистом Python.
Написан с нуля: свой TLS 1.3, своя реализация Reality, свой VLESS.

Работает с настоящими Xray-клиентами: **Happ**, **NekoBox**, **v2rayNG**.

---

## Возможности

- **TLS 1.3 с нуля** — свой handshake, key schedule, AEAD (X25519 + HKDF-SHA256 + AES-128-GCM)
- **REALITY** — маскировка под `ya.ru` (или другой сайт), устойчива к активному зондированию
- **VLESS** — TCP + UDP релей
- **Anti-replay** — защита от повторов session_id
- **Rate limiting** — бан IP после N попыток
- **Мультиюзер** — несколько UUID и short_id
- **Статистика** — uptime, соединения, трафик
- **Логи с уровнями** — DEBUG/INFO/WARN/ERROR, ротация в файл
- **Генератор ссылок** — vless:// + QR-код
- **CLI** — status, stop, users add/remove/list, link
- **Graceful shutdown** — корректное завершение по SIGINT/SIGTERM

---

## Быстрый старт

### Зависимости

    pip install cryptography kyber-py

Опционально для QR-кода:

    pip install qrcode

Требуется Python 3.10+. Если cryptography без ML-KEM — установи kyber-py.

### Запуск

    # Сгенерировать конфиг
    python main.py server noconfig 0.0.0.0

    # Обычный запуск
    python main.py server 0.0.0.0

В логе появится ссылка vless://... — импортируй её в Happ / NekoBox / v2rayNG.

### CLI

    python main.py status                        # работает ли сервер
    python main.py stop                          # остановить
    python main.py users list                    # список пользователей
    python main.py users add friend              # добавить друга
    python main.py users remove <uuid>           # удалить
    python main.py link friend 1.2.3.4 443       # ссылка для юзера
    python linkgen.py 1.2.3.4 443 friend --qr    # ссылка + QR

---

## Структура

    VPN/
    ├── main.py          — CLI и запуск
    ├── genconf.py       — генерация конфига
    ├── vpnconfig.py     — обёртка над config.json
    ├── vpnlog.py        — логирование (уровни, ротация)
    ├── vpnstats.py      — счётчики
    ├── vpnguard.py      — rate limiting
    ├── vpncli.py        — CLI-команды
    ├── server.py        — VLESS TCP/UDP сервер
    ├── sslfork.py       — TLS 1.3 + REALITY
    ├── reality_pq.py    — Reality-auth + anti-replay
    ├── linkgen.py       — генератор vless://
    ├── testClient.py    — тест VLESS
    ├── testClientTLS.py — тест TLS 1.3
    └── config.example.json

---

## Как работает REALITY

Xray REALITY маскирует VPN под обычный HTTPS-сайт.

### 1. session_id как скрытый канал

Клиент шифрует туда версию/timestamp/short_id:

    plaintext = [version(3)] [reserved(1)] [timestamp(4)] [short_id(8)]
    key       = HKDF(X25519_static_shared, salt=client_random[:20], info="REALITY")
    nonce     = client_random[20:32]
    AAD       = ClientHello с занулённым session_id

### 2. HMAC-подпись сертификата

Вместо стандартной криптографической подписи:

    signature = HMAC-SHA512(AuthKey, ed25519_public_key)

### 3. Fallback

Для чужих клиентов прозрачный TCP-прокси на dest. Сканер видит сертификат ya.ru и думает что это обычный сайт.

Подробнее — в sslfork.py и reality_pq.py.

---

## Конфигурация

config.json (генерируется автоматически, не коммитится):

| Поле | Описание | Default |
|------|----------|---------|
| uuid | UUID клиента | auto |
| private_key / public_key | X25519 ключи (hex) | auto |
| short_id | 8 байт в hex | auto |
| dest | сайт-маскировка | ya.ru:443 |
| listen_port | порт | 8443 |
| security | reality / tls / none | reality |
| debug | подробные логи | false |
| log_file | путь для логов | "" |
| stats_interval | интервал stats в секундах | 60 |
| replay_ttl | окно anti-replay | 300 |
| clienthello_timeout | таймаут ClientHello | 5 |
| handshake_timeout | таймаут handshake | 10 |
| idle_timeout | простой соединения | 300 |

---

## Развёртывание на VPS / Raspberry Pi

### Автоматический скрипт

    sudo ./setup.sh

Скрипт установит Python, создаст venv, настроит systemd, сгенерирует конфиг.

### Вручную

    python3 -m venv ~/vpn-env
    source ~/vpn-env/bin/activate
    pip install cryptography kyber-py
    python main.py server 0.0.0.0

### Systemd

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

## Безопасность

- Не выкладывай ссылку публично. UUID в ссылке = пароль.
- Не давай доступ третьим лицам. Это нарушает ст. 13.32 КоАП РФ.
- Reality на Python уязвим к новым версиям Xray. Если Xray поменяет формат session_id — сервер сломается.
- Своя криптография — риск. Мы используем проверенные примитивы (cryptography), но структура handshake написана самостоятельно.

---

## Что проверено

- Работает с Happ на Android
- Работает с NekoBox
- Работает с v2rayNG
- Тестирован на Termux
- Тестирован на Debian/Ubuntu
- Тестирован на Raspberry Pi 5

---

## Лицензия

MIT — используй, форкай, улучшай.

---

## Что дальше

- XTLS-Vision (padding) — для обфускации
- Множественные dest (SNI-routing)
- Веб-панель управления
- Мобильное приложение-обёртка

---

Написано как исследование протокола REALITY.
Не заменяет Xray-core, но показывает, что реализация на Python возможна.
