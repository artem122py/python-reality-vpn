# vpntraffic.py — лимиты трафика по пользователям
"""Проверяет, не превышен ли лимит трафика у пользователя.

Лимит задаётся в config.json:
  "traffic_limits_enabled": true
  "users": [
      {"name": "friend", "uuid": "...", "limit_bytes": 10737418240}
  ]

0 в limit_bytes = без лимита.
"""
from vpnlog import log


class TrafficLimiter:
    def __init__(self):
        self.enabled = False
        self.default_limit = 0
        self._uuid_to_limit = {}   # uuid_hex -> limit (0 = без лимита)
        self._uuid_to_name = {}    # uuid_hex -> name
        self._blocked = set()      # uuid_hex (забаненные по превышению)
        self._warned = set()       # чтобы не спамить в лог

    def load(self, cfg):
        self.enabled = cfg.get("traffic_limits_enabled", False)
        self.default_limit = int(cfg.get("traffic_limit_default", 0) or 0)
        self._uuid_to_limit = {}
        self._uuid_to_name = {}

        # Single-user
        if cfg.get("uuid"):
            uid = cfg["uuid"].replace("-", "").lower()
            limit = int(cfg.get("limit_bytes", self.default_limit) or 0)
            self._uuid_to_limit[uid] = limit
            self._uuid_to_name[uid] = "default"

        # Multi-user
        for u in cfg.get("users", []) or []:
            uid = (u.get("uuid") or "").replace("-", "").lower()
            if not uid:
                continue
            limit = int(u.get("limit_bytes", self.default_limit) or 0)
            self._uuid_to_limit[uid] = limit
            self._uuid_to_name[uid] = u.get("name", "?")

        if self.enabled:
            limits_desc = ", ".join(
                f"{self._uuid_to_name[k]}={self._fmt(self._uuid_to_limit[k])}"
                for k in self._uuid_to_limit
            )
            log.info(f"[traffic] enabled. limits: {limits_desc}")
        else:
            log.debug("[traffic] disabled")

    def check(self, uuid_bytes, stats):
        """
        Возвращает True, если пользователь МОЖЕТ подключаться (не превышен лимит).
        uuid_bytes — 16 байт UUID из VLESS-заголовка.
        stats — экземпляр Stats (vpnstats.stats).
        """
        if not self.enabled:
            return True

        uid = uuid_bytes.hex().lower()
        limit = self._uuid_to_limit.get(uid, self.default_limit)

        if limit <= 0:
            return True  # без лимита

        user_stat = stats.users.get(uid)
        if user_stat is None:
            return True  # ещё не подключался — ок

        used = user_stat.up + user_stat.down
        if used >= limit:
            if uid not in self._warned:
                name = self._uuid_to_name.get(uid, "?")
                log.warn(
                    f"[traffic] BLOCKED {name}: "
                    f"used {self._fmt(used)} >= limit {self._fmt(limit)}"
                )
                self._warned.add(uid)
            self._blocked.add(uid)
            return False

        return True

    def get_usage(self, uuid_bytes, stats):
        """Возвращает (used, limit, percent)."""
        uid = uuid_bytes.hex().lower()
        limit = self._uuid_to_limit.get(uid, self.default_limit)
        user_stat = stats.users.get(uid)
        used = (user_stat.up + user_stat.down) if user_stat else 0
        percent = (used / limit * 100) if limit > 0 else 0
        return used, limit, percent

    @staticmethod
    def _fmt(n):
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} PB"


# Глобальный экземпляр
limiter = TrafficLimiter()
