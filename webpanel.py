# webpanel.py — веб-панель на Flask
import json
import os
import secrets
import socket
import subprocess
import threading
import time

from flask import Flask, Response, redirect, render_template_string, request, jsonify

from vpnconfig import load_config_file, Config
from genconf import gen_uuid, gen_short_id
from linkgen import generate_link
from vpnstats import stats


CFG_PATH = "config.json"
WEB_CFG_PATH = "webpanel.json"


def _load_web_cfg():
    if not os.path.exists(WEB_CFG_PATH):
        cfg = {
            "username": "admin",
            "password": secrets.token_urlsafe(12),
            "listen_port": 9090,
            "listen_host": "127.0.0.1",
        }
        with open(WEB_CFG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        print(f"[webpanel] Создан {WEB_CFG_PATH}")
        print(f"[webpanel] login: {cfg['username']}")
        print(f"[webpanel] password: {cfg['password']}")
        return cfg
    with open(WEB_CFG_PATH) as f:
        return json.load(f)


WEB_CFG = _load_web_cfg()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)


# ---------- Auth (HTTP Basic) ----------

def check_auth(auth):
    if not auth:
        return False
    ok_user = secrets.compare_digest(auth.username, WEB_CFG["username"])
    ok_pass = secrets.compare_digest(auth.password, WEB_CFG["password"])
    return ok_user and ok_pass


@app.before_request
def require_auth():
    auth = request.authorization
    if not check_auth(auth):
        return Response(
            "Auth required", 401,
            {"WWW-Authenticate": 'Basic realm="VPN Panel"'},
        )


# ---------- Helpers ----------

def _is_server_running():
    try:
        cfg = load_config_file()
        port = cfg.get("listen_port", 8443)
    except Exception:
        port = 8443
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


# ---------- Templates ----------

BASE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} — Reality VPN</title>
<style>
body{font-family:system-ui,sans-serif;background:#1a1a1a;color:#eee;margin:0;padding:20px;max-width:1000px}
h1,h2{color:#4af}
a{color:#4af;text-decoration:none}
a:hover{text-decoration:underline}
table{border-collapse:collapse;width:100%;margin:10px 0}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #333}
th{background:#252525;color:#aaa}
.status-ok{color:#4f8;font-weight:bold}
.status-bad{color:#f84;font-weight:bold}
.card{background:#252525;padding:15px;border-radius:8px;margin:10px 0}
.btn{background:#4af;color:#111;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;font-size:14px}
.btn:hover{background:#6cf}
.btn-danger{background:#f44;color:#fff}
.btn-danger:hover{background:#f66}
input,select{background:#333;color:#eee;border:1px solid #555;padding:6px 10px;border-radius:4px;font-size:14px}
code{background:#333;padding:2px 6px;border-radius:3px;font-size:12px;word-break:break-all;display:inline-block}
.menu{margin:10px 0}
.menu a{margin-right:20px;font-size:16px}
pre{background:#333;padding:10px;border-radius:4px;overflow:auto}
</style>
</head>
<body>
<h1>Reality VPN Panel</h1>
<div class="menu">
<a href="/">Главная</a>
<a href="/users">Пользователи</a>
<a href="/stats">Статистика</a>
</div>
<hr>
{{ content|safe }}
</body>
</html>"""


def render(title, content):
    return render_template_string(BASE, title=title, content=content)


# ---------- Routes ----------

@app.route("/")
def index():
    running = _is_server_running()
    status = '<span class="status-ok">RUNNING</span>' if running else '<span class="status-bad">STOPPED</span>'
    try:
        cfg = load_config_file()
        port = cfg.get("listen_port", 8443)
        link = generate_link(cfg, "127.0.0.1", port)
    except Exception as e:
        port = "?"
        link = f"error: {e}"

    return render("Главная", f"""
<div class="card">
<h2>Сервер</h2>
<p>Статус: {status}</p>
<p>Порт: <b>{port}</b></p>
</div>
<div class="card">
<h2>Ссылка для подключения</h2>
<code>{link}</code>
</div>
<div class="card">
<h2>Управление</h2>
<p>Сервер управляется через CLI в Termux:</p>
<pre>python main.py stop
python main.py server 0.0.0.0</pre>
<p>Webpanel — только для просмотра и редактирования конфига.</p>
</div>
""")


@app.route("/users")
def users():
    try:
        cfg = load_config_file()
    except Exception as e:
        return render("Ошибка", f"<p class='status-bad'>{e}</p>")

    u_list = cfg.get("users", [])
    if not u_list and cfg.get("uuid"):
        u_list = [{"name": "default", "uuid": cfg["uuid"], "short_id": cfg["short_id"]}]

    rows = ""
    for u in u_list:
        rows += f"""<tr>
<td>{u.get('name', '?')}</td>
<td><code>{u.get('uuid', '?')}</code></td>
<td><code>{u.get('short_id', '?')}</code></td>
<td>
<form method="post" action="/users/remove" style="display:inline">
<input type="hidden" name="uuid" value="{u.get('uuid', '')}">
<button class="btn btn-danger" type="submit">Удалить</button>
</form>
</td>
</tr>"""

    return render("Пользователи", f"""
<div class="card">
<h2>Пользователи ({len(u_list)})</h2>
<table>
<tr><th>Имя</th><th>UUID</th><th>Short ID</th><th></th></tr>
{rows}
</table>
</div>
<div class="card">
<h2>Добавить пользователя</h2>
<form method="post" action="/users/add">
<input type="text" name="name" placeholder="имя" required>
<button class="btn" type="submit">Добавить</button>
</form>
</div>
""")


@app.route("/users/add", methods=["POST"])
def users_add():
    name = request.form.get("name", "").strip()
    if name:
        cfg = Config(CFG_PATH)
        cfg.load()
        data = cfg.data
        if "users" not in data:
            data["users"] = [{
                "name": "default",
                "uuid": data.get("uuid"),
                "short_id": data.get("short_id"),
            }]
        data["users"].append({
            "name": name,
            "uuid": gen_uuid(),
            "short_id": gen_short_id(),
        })
        with open(CFG_PATH, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    return redirect("/users")


@app.route("/users/remove", methods=["POST"])
def users_remove():
    uuid_val = request.form.get("uuid", "")
    if uuid_val:
        cfg = Config(CFG_PATH)
        cfg.load()
        data = cfg.data
        if "users" in data:
            data["users"] = [u for u in data["users"] if u.get("uuid") != uuid_val]
            with open(CFG_PATH, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
    return redirect("/users")


@app.route("/stats")
def stats_page():
    summary = stats.summary()
    return render("Статистика", f"""
<div class="card">
<h2>Статистика</h2>
<pre>{summary}</pre>
</div>
<div class="card">
<h2>JSON API</h2>
<p><a href="/api/stats">/api/stats</a></p>
</div>
""")


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "uptime": stats.uptime(),
        "total_connections": stats.total_connections,
        "active_connections": stats.active_connections,
        "tcp_connections": stats.tcp_connections,
        "udp_connections": stats.udp_connections,
        "total_up": stats.total_up,
        "total_down": stats.total_down,
        "failed_handshakes": stats.failed_handshakes,
        "auth_failures": stats.auth_failures,
        "replay_attacks": stats.replay_attacks,
    })


def main():
    host = WEB_CFG.get("listen_host", "127.0.0.1")
    port = WEB_CFG.get("listen_port", 9090)
    print(f"[webpanel] http://{host}:{port}")
    print(f"[webpanel] login: {WEB_CFG['username']}")
    print(f"[webpanel] password: {WEB_CFG['password']}")
    print("[webpanel] Ctrl+C для остановки")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
