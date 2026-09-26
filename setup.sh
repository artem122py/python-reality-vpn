#!/usr/bin/env bash
# setup.sh — автоматическая установка Reality VPN 2.1.0
# Поддерживает: Termux (Android), Debian, Ubuntu, Raspberry Pi OS, Fedora, Arch
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[X]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

echo
echo "=============================================="
echo "  Reality VPN 2.1.0 - установка"
echo "=============================================="
echo

# ---------- 1. Определить окружение ----------
IS_TERMUX=0
if [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=1
    ok "Обнаружен Termux (Android)"
else
    ok "Обнаружена Linux-система: $(uname -s)"
fi

# ---------- 2. Проверить Python ----------
info "Проверяю Python..."
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    if [ "$IS_TERMUX" = "1" ]; then
        info "Устанавливаю Python через pkg..."
        pkg install -y python
    else
        if command -v apt >/dev/null 2>&1; then
            sudo apt update && sudo apt install -y python3 python3-pip python3-venv
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y python3 python3-pip
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm python python-pip
        else
            fail "Не удалось установить Python: неизвестный пакетный менеджер"
        fi
    fi
fi

PY=$(command -v python3 || command -v python)
PY_VER=$("$PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ok "Python $PY_VER ($PY)"

if ! "$PY" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    fail "Требуется Python >= 3.10, найден $PY_VER"
fi

# ---------- 3. Установить зависимости ----------
info "Устанавливаю зависимости..."

if [ "$IS_TERMUX" = "1" ]; then
    pkg install -y openssl libffi rust binutils 2>/dev/null || true
fi

"$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
"$PY" -m pip install cryptography kyber-py || fail "Не удалось установить cryptography/kyber-py"

if "$PY" -m pip install qrcode 2>/dev/null; then
    ok "qrcode установлен (QR-генерация)"
else
    warn "qrcode не установлен (опционально)"
fi

# ---------- 4. Установить проект ----------
info "Устанавливаю reality-vpn..."
"$PY" -m pip install -e . || fail "pip install -e . упал"
ok "reality-vpn установлен"

# ---------- 5. Проверка импорта ----------
info "Проверяю импорт..."
"$PY" -c "import reality_vpn; print('  version:', reality_vpn.__version__)" || fail "Импорт reality_vpn не работает"
"$PY" -c "from reality_vpn.server.server import VlessServer; print('  server module ok')" || fail "Импорт VlessServer не работает"

# ---------- 6. Конфиг ----------
if [ ! -f config.json ]; then
    info "Генерирую config.json..."
    "$PY" -c "from reality_vpn.utils.genconf import gen_config; gen_config()"
    ok "config.json создан"
else
    ok "config.json уже существует"
fi

# ---------- 7. Тесты ----------
info "Запускаю тесты..."
if "$PY" -m pytest src/reality_vpn/tests/ -q 2>/dev/null; then
    ok "Тесты прошли"
else
    warn "Тесты не прошли (не критично)"
fi

# ---------- 8. Systemd (только Linux, не Termux) ----------
if [ "$IS_TERMUX" = "0" ] && command -v systemctl >/dev/null 2>&1; then
    echo
    info "Установить systemd-сервис? (y/N)"
    read -r INSTALL_SYSTEMD
    if [ "$INSTALL_SYSTEMD" = "y" ] || [ "$INSTALL_SYSTEMD" = "Y" ]; then
        USER_NAME=$(whoami)
        SERVICE_FILE="/etc/systemd/system/reality-vpn.service"
        sudo tee "$SERVICE_FILE" >/dev/null <<SYSTEMD_EOF
[Unit]
Description=Reality VPN
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$PROJECT_DIR
ExecStart=$PY -m reality_vpn server 0.0.0.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
        sudo systemctl daemon-reload
        sudo systemctl enable reality-vpn
        ok "Systemd-сервис установлен: reality-vpn.service"
        info "Запуск: sudo systemctl start reality-vpn"
        info "Логи:   sudo journalctl -u reality-vpn -f"
    fi
fi

# ---------- 9. Финальная подсказка ----------
echo
echo "=============================================="
echo "  Установка завершена"
echo "=============================================="
echo
if [ "$IS_TERMUX" = "1" ]; then
    echo "  Запуск:"
    echo "    python -m reality_vpn server 0.0.0.0"
    echo
    echo "  Ссылка появится в логе после запуска."
    echo "  Импортируй её в Happ / NekoBox / v2rayNG."
else
    echo "  Запуск:"
    echo "    python -m reality_vpn server 0.0.0.0"
    echo "  или через systemd:"
    echo "    sudo systemctl start reality-vpn"
fi
echo
echo "  Документация: README.md"
echo "  Проблемы:     https://github.com/artem122py/python-reality-vpn/issues"
echo
