# vpnlog.py
"""
Полноценное логирование: уровни, цвета, файл с ротацией.
Использование:
    from reality_vpn.utils.log import log
    log.info("...")
    log.debug("...")
    log.warn("...")
    log.error("...")
"""
import os
import sys
from datetime import datetime


import os as _os
PROJECT_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))))

class _Logger:
    LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}

    COLORS = {
        "DEBUG": "\033[90m",   # серый
        "INFO":  "\033[36m",   # циан
        "WARN":  "\033[33m",   # жёлтый
        "ERROR": "\033[31m",   # красный
        "RESET": "\033[0m",
    }

    def __init__(self):
        self.level = "INFO"
        self.file = None
        self.use_color = sys.stdout.isatty()
        self.max_bytes = 5 * 1024 * 1024   # 5 MB
        self.backup_count = 3
        self._lines_written = 0

    def configure(self, debug=False, log_file=None, use_color=None,
                  max_bytes=None, backup_count=None):
        self.level = "DEBUG" if debug else "INFO"
        if use_color is not None:
            self.use_color = use_color
        if max_bytes is not None:
            self.max_bytes = max_bytes
        if backup_count is not None:
            self.backup_count = backup_count
        if log_file:
            self._open_file(log_file)

    def _open_file(self, path):
        if self.file:
            try: self.file.close()
            except Exception: pass
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            self.file = open(path, "a", buffering=1, encoding="utf-8")
            self._lines_written = 0
        except Exception as e:
            print(f"[vpnlog] cannot open {path}: {e}")
            self.file = None

    def _rotate_if_needed(self):
        if not self.file:
            return
        try:
            if self.file.tell() < self.max_bytes:
                return
            self.file.close()
            path = self.file.name
            # Сдвигаем бэкапы
            for i in range(self.backup_count - 1, 0, -1):
                old = f"{path}.{i}"
                new = f"{path}.{i+1}"
                if os.path.exists(old):
                    if os.path.exists(new):
                        os.remove(new)
                    os.rename(old, new)
            # Текущий -> .1
            if os.path.exists(path):
                if os.path.exists(f"{path}.1"):
                    os.remove(f"{path}.1")
                os.rename(path, f"{path}.1")
            self.file = open(path, "a", buffering=1, encoding="utf-8")
            self._lines_written = 0
        except Exception:
            pass

    # Сообщения, которые не стоит показывать как ERROR
    NOISE_PATTERNS = (
        "IncompleteReadError",
        "ConnectionResetError",
        "BrokenPipeError",
        "client closed",
        "0 bytes read on a total of 5",
    )

    def _emit(self, level, msg):
        if self.LEVELS[level] < self.LEVELS[self.level]:
            return

        # Приглушить шум: понизить ERROR до DEBUG, если это шум
        if level == "ERROR":
            for pattern in self.NOISE_PATTERNS:
                if pattern in msg:
                    if self.LEVELS["DEBUG"] < self.LEVELS[self.level]:
                        return
                    level = "DEBUG"
                    break

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plain = f"[{ts}] [{level:5}] {msg}"

        # Консоль
        if self.use_color:
            c = self.COLORS.get(level, "")
            r = self.COLORS["RESET"]
            print(f"{c}{plain}{r}", flush=True)
        else:
            print(plain, flush=True)

        # Файл
        if self.file:
            try:
                self.file.write(plain + "\n")
                self._lines_written += 1
                if self._lines_written % 100 == 0:
                    self._rotate_if_needed()
            except Exception:
                pass

    def debug(self, msg): self._emit("DEBUG", msg)
    def info(self, msg):  self._emit("INFO", msg)
    def warn(self, msg):  self._emit("WARN", msg)
    def error(self, msg): self._emit("ERROR", msg)

    def exception(self, msg):
        """Логирует сообщение + traceback."""
        import traceback
        tb = traceback.format_exc()
        self._emit("ERROR", f"{msg}\n{tb}")


log = _Logger()


# Удобные псевдонимы на случай старого стиля
debug = log.debug
info = log.info
warn = log.warn
error = log.error