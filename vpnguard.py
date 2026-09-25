# vpnguard.py
"""Защита от брутфорса и DoS."""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_attempts=20, window=60, ban_time=600):
        self.max_attempts = max_attempts
        self.window = window
        self.ban_time = ban_time
        self.attempts = defaultdict(deque)
        self.banned = {}

    def is_banned(self, ip):
        if ip in self.banned:
            if time.time() < self.banned[ip]:
                return True
            else:
                del self.banned[ip]
        return False

    def record_attempt(self, ip):
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


guard = RateLimiter(max_attempts=20, window=60, ban_time=600)
