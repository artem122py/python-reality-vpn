# vpncli.py
"""CLI команды для управления VPN-сервером."""
import os
import sys
import json
import signal
from reality_vpn.cli.config import load_config_file, Config
from reality_vpn.utils.genconf import gen_uuid, gen_short_id




def cmd_traffic():
    """Показать использование трафика."""
    from reality_vpn.utils.stats import stats
    from reality_vpn.utils.traffic import limiter

    stats.load()
    try:
        cfg = load_config_file()
        stats.load_user_map(cfg)
        limiter.load(cfg)
    except Exception as e:
        print(f"config error: {e}")
        return

    if not limiter.enabled:
        print("traffic limits: DISABLED (traffic_limits_enabled = false)")
        print()
        print("=== per-user usage (без лимитов) ===")
        print(stats.per_user_summary())
        return

    print("traffic limits: ENABLED")
    print()

    # Собираем всех известных пользователей
    all_users = {}
    for uid, us in stats.users.items():
        all_users[uid] = us

    # Добавляем тех, кто в конфиге, но ещё не подключался
    for uid, name in limiter._uuid_to_name.items():
        if uid not in all_users:
            from reality_vpn.utils.stats import UserStat
            us = UserStat(name, uid)
            all_users[uid] = us

    print("=== per-user usage ===")
    for uid, us in all_users.items():
        limit = limiter._uuid_to_limit.get(uid, limiter.default_limit)
        used = us.up + us.down
        if limit > 0:
            percent = used / limit * 100
            bar_len = min(20, int(percent / 5))
            bar = "█" * bar_len + "░" * (20 - bar_len)
            status = " ❌BLOCKED" if percent >= 100 else ""
            print(f"  {us.name:<16} [{bar}] {percent:5.1f}% "
                  f"({limiter._fmt(used)} / {limiter._fmt(limit)}){status}")
        else:
            print(f"  {us.name:<16} (no limit) {limiter._fmt(used)}")


def cmd_version():
    """Показать версию сервера."""
    try:
        from reality_vpn.server.server import SERVER_VERSION, BUILD_DATE
        print(f"VPN Server v{SERVER_VERSION} (build {BUILD_DATE})")
    except Exception:
        print("VPN Server (version unknown)")
    import sys
    print(f"Python: {sys.version.split()[0]}")


def cmd_status():
    """Показывает, работает ли сервер (по занятости порта)."""
    import socket
    try:
        cfg = load_config_file()
        port = cfg.get("listen_port", 8443)
    except Exception:
        port = 8443

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        print(f"server: NOT RUNNING (port {port} free)")
    except OSError:
        print(f"server: RUNNING (port {port} busy)")
    finally:
        s.close()

def cmd_stop():
    """Находит и останавливает сервер через ps."""
    import subprocess
    try:
        result = subprocess.run(
            ["ps", "-ef"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception as e:
        print(f"failed to run ps: {e}")
        return

    pids = []
    for line in result.stdout.splitlines():
        if "main.py server" in line and "grep" not in line:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                    pids.append(pid)
                except ValueError:
                    pass

    if not pids:
        print("server not running")
        return

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"sent SIGTERM to pid {pid}")
        except Exception as e:
            print(f"failed to kill {pid}: {e}")

def cmd_users_list():
    """Список пользователей."""
    try:
        cfg = load_config_file()
    except Exception as e:
        print(f"config error: {e}")
        return

    users = cfg.get("users", [])
    if not users:
        # single-user mode
        print("=== single user mode ===")
        print(f"  uuid      = {cfg['uuid']}")
        print(f"  short_id  = {cfg['short_id']}")
        return

    print(f"=== {len(users)} user(s) ===")
    for i, u in enumerate(users):
        print(f"  [{i}] name={u.get('name', '?')}")
        print(f"       uuid      = {u.get('uuid', '?')}")
        print(f"       short_id  = {u.get('short_id', '?')}")


def cmd_users_add(name, uuid=None, short_id=None):
    """Добавить пользователя."""
    cfg = Config()
    cfg.load()
    data = cfg.data

    if "users" not in data:
        # мигрируем single-user в список
        data["users"] = [{
            "name": "default",
            "uuid": data.get("uuid"),
            "short_id": data.get("short_id"),
        }]

    uuid = uuid or gen_uuid()
    short_id = short_id or gen_short_id()

    for u in data["users"]:
        if u.get("uuid") == uuid:
            print(f"user with uuid {uuid} already exists")
            return

    data["users"].append({
        "name": name,
        "uuid": uuid,
        "short_id": short_id,
    })

    with open("config.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"user '{name}' added:")
    print(f"  uuid      = {uuid}")
    print(f"  short_id  = {short_id}")


def cmd_users_remove(uuid):
    """Удалить пользователя по UUID."""
    cfg = Config()
    cfg.load()
    data = cfg.data

    if "users" not in data:
        print("no users list (single-user mode)")
        return

    before = len(data["users"])
    data["users"] = [u for u in data["users"] if u.get("uuid") != uuid]
    after = len(data["users"])

    if before == after:
        print(f"user {uuid} not found")
        return

    with open("config.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"removed {before - after} user(s)")


def cmd_link(name=None, host=None, port=None):
    """Сгенерировать ссылку vless:// для пользователя."""
    from reality_vpn.utils.linkgen import generate_link
    try:
        cfg = load_config_file()
    except Exception as e:
        print(f"config error: {e}")
        return

    host = host or "127.0.0.1"
    port = int(port) if port else cfg.get("listen_port", 8443)

    if name:
        users = cfg.get("users", [])
        target = None
        for u in users:
            if u.get("name") == name:
                target = u
                break
        if not target:
            print(f"user '{name}' not found")
            return
        # подменяем uuid/short_id для генерации
        cfg["uuid"] = target["uuid"]
        cfg["short_id"] = target["short_id"]

    link = generate_link(cfg, host, port, name or "vpn")
    print(link)


def cmd_users(args):
    if not args:
        cmd_users_list()
        return
    action = args[0]
    if action == "list":
        cmd_users_list()
    elif action == "usage":
        cmd_traffic()
    elif action == "add":
        if len(args) < 2:
            print("usage: users add <name> [uuid] [short_id]")
            return
        cmd_users_add(args[1],
                      args[2] if len(args) > 2 else None,
                      args[3] if len(args) > 3 else None)
    elif action == "remove":
        if len(args) < 2:
            print("usage: users remove <uuid>")
            return
        cmd_users_remove(args[1])
    else:
        print(f"unknown action: {action}")


def cmd_stats():
    """Показать статистику сервера."""
    from reality_vpn.utils.stats import stats
    stats.load()
    try:
        cfg = load_config_file()
        stats.load_user_map(cfg)
    except Exception:
        pass

    print("=== global ===")
    print(f"  {stats.summary()}")
    print()
    print("=== per-user ===")
    print(stats.per_user_summary())
