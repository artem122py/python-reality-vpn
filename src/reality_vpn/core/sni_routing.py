# src/reality_vpn/core/sni_routing.py
"""SNI-роутинг: для каждого SNI свой dest.

Использование:
    from reality_vpn.core.sni_routing import build_router_from_config

    router = build_router_from_config(cfg)
    dest = router.resolve(sni)   # "ya.ru:443" или default
"""
from reality_vpn.utils.log import log


class SniRouter:
    """Резолвер: SNI → (host, port)."""

    def __init__(self, default_dest, routes=None):
        """
        default_dest — "host:port" для неизвестных SNI.
        routes — dict {sni: "host:port"}.
        """
        self.default_dest = default_dest
        self.routes = routes or {}

    def resolve(self, sni):
        """Возвращает "host:port" для SNI. Если sni пустой — default."""
        if not sni:
            return self.default_dest

        sni = sni.lower().strip()

        # Точное совпадение
        if sni in self.routes:
            return self.routes[sni]

        # Wildcard: *.example.com
        parts = sni.split(".")
        for i in range(1, len(parts)):
            wildcard = "*." + ".".join(parts[i:])
            if wildcard in self.routes:
                return self.routes[wildcard]

        return self.default_dest

    def split_dest(self, dest):
        """Разбивает "host:port" на (host, port)."""
        if ":" in dest:
            host, port_str = dest.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        else:
            host = dest
            port = 443
        return host, port

    @classmethod
    def from_config(cls, cfg):
        """Создаёт роутер из конфига.

        cfg["dest"] — default "host:port".
        cfg["sni_routes"] — {"sni": "host:port", ...}.
        """
        default = cfg.get("dest", "ya.ru:443")
        routes = cfg.get("sni_routes", {}) or {}

        if routes:
            # Логируем один раз при загрузке (log.debug — не при INFO)
            log.debug(f"[sni] routes loaded: {len(routes)}")
            for sni, dest in list(routes.items())[:5]:
                log.debug(f"[sni]   {sni} -> {dest}")
            if len(routes) > 5:
                log.debug(f"[sni]   ... и ещё {len(routes) - 5}")

        return cls(default, routes)


def build_router_from_config(cfg):
    return SniRouter.from_config(cfg)
