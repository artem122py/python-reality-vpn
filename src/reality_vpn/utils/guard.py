# vpnguard.py
"""Защита от брутфорса и DoS. Приватные IP не банятся."""
import time
from collections import defaultdict, deque


def _is_private_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 127: return True
        if a == 10: return True
        if a == 192 and b == 168: return True
        if a == 172 and 16 <= b <= 31: return True
    except Exception:
        pass
    return False


class RateLimiter:
    def __init__(self, max_attempts=200, window=60, ban_time=60):
        self.max_attempts = max_attempts
        self.window = window
        self.ban_time = ban_time
        self.attempts = defaultdict(deque)
        self.banned = {}

    def is_banned(self, ip):
        if _is_private_ip(ip):
            return False
        if ip in self.banned:
            if time.time() < self.banned[ip]:
                return True
            else:
                del self.banned[ip]
        return False

    def record_attempt(self, ip):
        if _is_private_ip(ip):
            return False
        now = time.time()
        dq = self.attempts[ip]
        while dq and now - dq[0] > self.window:
            dq.popleft()
        dq.append(now)
        if len(dq) > self.max_attempts:
            self.banned[ip] = now + self.ban_time
            dq.clear()
            return True
        return False

    def cleanup(self):
        now = time.time()
        self.banned = {ip: t for ip, t in self.banned.items() if t > now}
        for ip in list(self.attempts.keys()):
            dq = self.attempts[ip]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if not dq:
                del self.attempts[ip]


guard = RateLimiter(max_attempts=200, window=60, ban_time=60)
