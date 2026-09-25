#!/data/data/com.termux/files/usr/bin/bash
# release.sh — релиз 2.0.0 + коммит + push
set -e
cd /storage/emulated/0/VPN

VERSION="2.0.0"
DATE="2026-09-25"

echo "=== [1/8] Обновляю версии в коде ==="
sed -i "s/__version__ = .*/__version__ = \"$VERSION\"/" src/reality_vpn/__init__.py
sed -i "s/SERVER_VERSION = .*/SERVER_VERSION = \"$VERSION\"/" src/reality_vpn/server/server.py
sed -i "s/version = .*/version = \"$VERSION\"/" pyproject.toml
grep -H "VERSION\|version" src/reality_vpn/__init__.py src/reality_vpn/server/server.py pyproject.toml | grep -v BUILD

echo ""
echo "=== [2/8] Обновляю badge в README ==="
sed -i 's/version-1\.[01]\.[01]-blue/version-2.0.0-blue/g' README.md README_ENG.md
# Если badge не было — добавляем
grep -q "version-2.0.0" README.md || sed -i 's|^\[!\[Python\]|[![Version](https://img.shields.io/badge/version-2.0.0-blue)]()\n[![Python]|' README.md
grep -q "version-2.0.0" README_ENG.md || sed -i 's|^\[!\[Python\]|[![Version](https://img.shields.io/badge/version-2.0.0-blue)]()\n[![Python]|' README_ENG.md
grep -c "version-2.0.0" README.md README_ENG.md

echo ""
echo "=== [3/8] Проверяю импорты и тесты ==="
python -c "import reality_vpn; print('package version:', reality_vpn.__version__)"
python -c "from reality_vpn.server.server import SERVER_VERSION; print('server version:', SERVER_VERSION)"
python -m pytest src/reality_vpn/tests/ -q 2>&1 | tail -3

echo ""
echo "=== [4/8] Проверяю git status ==="
if git status --porcelain | grep -q "config.json\|stats.json\|vpn.log\|webpanel.json"; then
    echo "!! ОПАСНО: секреты в git. Останавливаюсь."
    git status --porcelain | grep -E "config.json|stats.json|vpn.log|webpanel.json"
    exit 1
fi
echo "ok: секретов нет"
git status --short | head -20

echo ""
echo "=== [5/8] Коммит ==="
git add -A
git commit -m "Release v$VERSION" -m "SNI-routing, package structure, improved UDP, traffic limits" || echo "(нечего коммитить или ошибка)"

echo ""
echo "=== [6/8] Тег ==="
git tag -a "v$VERSION" -m "v$VERSION" -f

echo ""
echo "=== [7/8] Push ==="
git push || echo "!! push упал — проверь токен/SSH"

echo ""
echo "=== [8/8] Push тега ==="
git push --tags -f || echo "!! tags push упал"

echo ""
echo "=== ИТОГ ==="
git log --oneline | head -3
git tag -l

echo ""
echo "Готово. Проверь на GitHub:"
echo "  https://github.com/artem122py/python-reality-vpn/releases"
