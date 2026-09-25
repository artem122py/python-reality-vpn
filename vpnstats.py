# vpnstats.py — глобальные + per-user счётчики
import os
import json
import time
import threading
from collections import defaultdict


STATS_FILE = "stats.json"
SAVE_INTERVAL = 30  # сек


class UserStat:
    __slots__ = ("name", "uuid", "up", "down", "conns", "last_seen")

    def __init__(self, name, uuid):
        self.name = name
        self.uuid = uuid
        self.up = 0
        self.down = 0
        self.conns = 0
        self.last_seen = 0

    def to_dict(self):
        return {
            "name": self.name,
            "uuid": self.uuid,
            "up": self.up,
            "down": self.down,
            "conns": self.conns,
            "last_seen": self.last_seen,
        }


class Stats:
    def __init__(self):
        self.start_time = time.time()
        self.total_connections = 0
        self.active_connections = 0
        self.tcp_connections = 0
        self.udp_connections = 0
        self.total_up = 0
        self.total_down = 0
        self.failed_handshakes = 0
        self.auth_failures = 0
        self.replay_attacks = 0
        self.errors = 0

        # per-user
        self.users = {}                # uuid_hex -> UserStat
        self._uuid_to_name = {}        # uuid_hex -> name
        self._lock = threading.Lock()
        self._dirty = False
        self._last_save = 0

    # ---------- инициализация из конфига ----------

    def load_user_map(self, cfg):
        """Строит маппинг UUID → имя из конфига."""
        with self._lock:
            self._uuid_to_name = {}
            if cfg.get("uuid"):
                self._uuid_to_name[cfg["uuid"].replace("-", "").lower()] = "default"
            for u in cfg.get("users", []) or []:
                uid = (u.get("uuid") or "").replace("-", "").lower()
                if uid:
                    self._uuid_to_name[uid] = u.get("name", "?")

    # ---------- общие счётчики ----------

    def on_connection(self):
        self.total_connections += 1
        self.active_connections += 1

    def on_disconnect(self):
        if self.active_connections > 0:
            self.active_connections -= 1

    def on_tcp(self):
        self.tcp_connections += 1

    def on_udp(self):
        self.udp_connections += 1

    def add_up(self, n):
        self.total_up += n

    def add_down(self, n):
        self.total_down += n

    def on_handshake_fail(self):
        self.failed_handshakes += 1

    def on_auth_fail(self):
        self.auth_failures += 1

    def on_replay(self):
        self.replay_attacks += 1

    def on_error(self):
        self.errors += 1

    # ---------- per-user ----------

    def on_user_connect(self, uuid_bytes):
        """uuid_bytes — 16 сырых байт."""
        uid = uuid_bytes.hex().lower()
        name = self._uuid_to_name.get(uid, "unknown")
        with self._lock:
            if uid not in self.users:
                self.users[uid] = UserStat(name, uid)
            us = self.users[uid]
            us.conns += 1
            us.last_seen = int(time.time())
            self._dirty = True

    def add_user_up(self, uuid_bytes, n):
        uid = uuid_bytes.hex().lower()
        with self._lock:
            us = self.users.get(uid)
            if us:
                us.up += n
                self._dirty = True

    def add_user_down(self, uuid_bytes, n):
        uid = uuid_bytes.hex().lower()
        with self._lock:
            us = self.users.get(uid)
            if us:
                us.down += n
                self._dirty = True

    # ---------- вывод ----------

    def uptime(self):
        return int(time.time() - self.start_time)

    @staticmethod
    def format_bytes(n):
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} PB"

    def summary(self):
        u = self.uptime()
        h, rem = divmod(u, 3600)
        m, s = divmod(rem, 60)
        return (
            f"uptime {h}h{m:02d}m{s:02d}s | "
            f"conns {self.total_connections} "
            f"(tcp {self.tcp_connections}, udp {self.udp_connections}) | "
            f"active {self.active_connections} | "
            f"up {self.format_bytes(self.total_up)} | "
            f"down {self.format_bytes(self.total_down)} | "
            f"hs_fail {self.failed_handshakes} | "
            f"auth_fail {self.auth_failures} | "
            f"replay {self.replay_attacks} | "
            f"errors {self.errors}"
        )

    def per_user_summary(self):
        lines = []
        with self._lock:
            users = sorted(self.users.values(),
                           key=lambda x: x.up + x.down, reverse=True)
        for u in users:
            last = "never"
            if u.last_seen:
                last = time.strftime("%Y-%m-%d %H:%M",
                                     time.localtime(u.last_seen))
            lines.append(
                f"  {u.name:<16} conns={u.conns:<6} "
                f"up={self.format_bytes(u.up):<10} "
                f"down={self.format_bytes(u.down):<10} "
                f"last={last}"
            )
        return "\n".join(lines) if lines else "  (no users)"

    # ---------- сохранение ----------

    def load(self):
        if not os.path.exists(STATS_FILE):
            return
        try:
            with open(STATS_FILE) as f:
                data = json.load(f)
            for uid, u in data.get("users", {}).items():
                us = UserStat(u.get("name", "?"), uid)
                us.up = u.get("up", 0)
                us.down = u.get("down", 0)
                us.conns = u.get("conns", 0)
                us.last_seen = u.get("last_seen", 0)
                self.users[uid] = us
        except Exception:
            pass

    def save(self, force=False):
        now = time.time()
        if not force and now - self._last_save < SAVE_INTERVAL:
            return
        if not self._dirty and not force:
            return
        with self._lock:
            data = {
                "users": {uid: u.to_dict() for uid, u in self.users.items()},
                "saved_at": int(now),
            }
            try:
                with open(STATS_FILE, "w") as f:
                    json.dump(data, f, indent=2)
                self._dirty = False
                self._last_save = now
            except Exception:
                pass


stats = Stats()
