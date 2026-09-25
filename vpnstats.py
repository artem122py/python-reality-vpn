# vpnstats.py
"""Счётчики для мониторинга VPN-сервера."""
import time


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
            f"replay {self.replay_attacks}"
        )


stats = Stats()
