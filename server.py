# server.py
import asyncio
import os
import signal
import struct
import socket
import uuid as uuidlib

from sslfork import wrap_server
from vpnstats import stats
from vpnguard import guard
from vpnlog import log
from linkgen import generate_link


def is_local_ip(peer):
    """True если peer — localhost (клиент на том же устройстве)."""
    if not peer:
        return False
    ip = peer[0] if isinstance(peer, tuple) else peer
    return ip in ("127.0.0.1", "::1", "localhost")




VERSION = 0x00
CMD_TCP = 0x01
CMD_UDP = 0x02
CMD_MUX = 0x03

SERVER_VERSION = "1.0.0"
BUILD_DATE = "2026-09-25"
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x02
ATYP_IPV6 = 0x03


class VlessServer:
    def __init__(self, cfg, addr):
        self.cfg = cfg
        self.addr = addr
        self.port = cfg.get("listen_port", 8443)
        # мультиюзер
        self.valid_uuids = set()
        if cfg.get("uuid"):
            self.valid_uuids.add(uuidlib.UUID(cfg["uuid"]).bytes)
        if cfg.get("users"):
            for u in cfg["users"]:
                try:
                    self.valid_uuids.add(uuidlib.UUID(u["uuid"]).bytes)
                except Exception:
                    pass
        self.uuid_bytes = uuidlib.UUID(cfg["uuid"]).bytes if cfg.get("uuid") else None
        self.one_shot = False
        self._done = asyncio.Event()

    async def run(self):
        # Игнорируем SIGPIPE — иначе падает при write в закрытый сокет
        try:
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        except (AttributeError, ValueError):
            pass  # Windows или не-главный поток

        # Предупреждение о beta-фиче Vision
        if self.cfg.get("use_vision", False):
            log.warn("=" * 60)
            log.warn("ВНИМАНИЕ: use_vision = True")
            log.warn("XTLS-Vision — BETA. НЕ работает с Happ/NekoBox.")
            log.warn("Используйте ссылку БЕЗ flow=xtls-rprx-vision.")
            log.warn("Если VPN не работает — установите use_vision = False")
            log.warn("=" * 60)

        # Загружаем статистику
        stats.load()
        stats.load_user_map(self.cfg)
        log.info(f"[stats] loaded: {len(stats.users)} user(s)")
        # Graceful shutdown через threading.Event
        # (loop.add_signal_handler НЕ работает в Termux/Android)
        import threading
        self._stop_flag = threading.Event()

        def _on_signal(signum, frame):
            log.info(f"signal {signum} received, shutting down...")
            self._stop_flag.set()

        try:
            signal.signal(signal.SIGINT, _on_signal)
            signal.signal(signal.SIGTERM, _on_signal)
        except Exception as e:
            log.warn(f"cannot install signal handlers: {e}")

        server = await asyncio.start_server(
            self.handle_client, self.addr, self.port,
            reuse_address=True,
        )
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        log.info(f"VLESS listening on {addrs}")
        log.info(f"Version: {SERVER_VERSION} (build {BUILD_DATE})")

        display_host = self._pick_display_host()
        try:
            link_no = generate_link(self.cfg, display_host, self.port,
                                    "vpn", with_vision=False)
            log.info(f"VLESS Link (no vision): {link_no}")

            # Ссылка с Vision — только если включён в конфиге
            if self.cfg.get("use_vision", False):
                link_vis = generate_link(self.cfg, display_host, self.port,
                                         "vpn-vision", with_vision=True)
                log.info(f"VLESS Link (vision):    {link_vis}")
        except Exception as e:
            log.warn(f"link generation failed: {e}")

        if self.cfg.get("stats_interval", 60) > 0:
            asyncio.create_task(self._stats_loop())

        async with server:
            serve_task = asyncio.create_task(server.serve_forever())
            while not self._stop_flag.is_set():
                if self.one_shot and self._done.is_set():
                    log.info("[*] one_shot: shutting down")
                    break
                await asyncio.sleep(0.3)

            log.info("[*] stopping...")

            # 1. Закрываем listener (новые коннекты не принимаются)
            server.close()

            # 2. Отменяем serve_task — НЕ ждём его await,
            #    иначе виснем на wait_closed, который ждёт активные соединения
            serve_task.cancel()

            # 3. Отменяем все остальные задачи (активные handlers)
            for task in asyncio.all_tasks():
                if task is asyncio.current_task() or task is serve_task:
                    continue
                task.cancel()

            # 4. Даём 1 сек на отмену, но не ждём бесконечно
            try:
                await asyncio.wait_for(serve_task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

            log.info(f"[stats] final: {stats.summary()}")
            log.info(f"[stats/users]\n{stats.per_user_summary()}")
            stats.save(force=True)


    async def _stats_loop(self):
        interval = self.cfg.get("stats_interval", 60)
        counter = 0
        while True:
            await asyncio.sleep(interval)
            log.info(f"[stats] {stats.summary()}")
            log.info(f"[stats/users]\n{stats.per_user_summary()}")
            stats.save()
            counter += 1
            if counter % 5 == 0:
                try:
                    from vpnguard import guard
                    guard.cleanup()
                except Exception:
                    pass

    def _pick_display_host(self):
        a = self.addr
        if a in ("0.0.0.0", "::", ""):
            try:
                hostname = socket.gethostname()
                candidates = socket.gethostbyname_ex(hostname)[2]
            except OSError:
                candidates = []
            for ip in candidates:
                if not ip.startswith("127."):
                    return ip
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.2)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except OSError:
                return "127.0.0.1"
        return a

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"

        # localhost никогда не баним (это может быть сам клиент на телефоне)
        is_local = ip in ("127.0.0.1", "::1", "localhost")

        if not is_local and guard.is_banned(ip):
            log.debug(f"{peer}: BANNED, closing")
            try: writer.close()
            except Exception: pass
            return

        try:
            await self._handle_client_inner(reader, writer, peer)
        except Exception as e:
            log.error(f"{peer}: {type(e).__name__}: {e}")
        finally:
            if self.one_shot:
                self._done.set()

    async def _handle_client_inner(self, reader, writer, peer):
        reader, writer = await wrap_server(reader, writer, self.cfg)
        if reader is None:
            return

        hdr = await self._read_vless_header(reader)
        if hdr is None:
            pass  # bad header - шум
            if not is_local_ip(peer):
                guard.record_attempt(peer[0] if peer else "?")
            return

        uuid_got, cmd, host, port, flow = hdr

        if uuid_got not in self.valid_uuids:
            log.warn(f"{peer}: uuid mismatch")
            if not is_local_ip(peer):
                guard.record_attempt(peer[0] if peer else "?")
            return

        # Per-user: отметить подключение
        stats.on_user_connect(uuid_got)

        if cmd == CMD_UDP:
            await self._handle_udp(reader, writer, host, port, peer)
            return
        if cmd == CMD_MUX:
            log.debug(f"{peer}: Mux not implemented")
            return
        if cmd != CMD_TCP:
            log.debug(f"{peer}: unknown command {cmd}")
            return

        writer.write(b"\x00\x00")
        await writer.drain()

        # XTLS-Vision — включается ПОСЛЕ VLESS-заголовка
        if flow == "xtls-rprx-vision" and self.cfg.get("use_vision", False):
            try:
                from vision import enable_vision_after_header
                log.info("[vision] enabling for this session")
                reader, writer = await enable_vision_after_header(
                    reader, writer, uuid_got, self.cfg,
                )
            except Exception as e:
                log.error(f"[vision] enable failed: {type(e).__name__}: {e}")

        log.info(f"{peer} -> {host}:{port}")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)

            # TCP_NODELAY + keepalive
            try:
                sock = remote_writer.get_extra_info("socket")
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    # Linux: TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
                    if hasattr(socket, "TCP_KEEPIDLE"):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    if hasattr(socket, "TCP_KEEPINTVL"):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    if hasattr(socket, "TCP_KEEPCNT"):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except Exception as e:
                log.debug(f"keepalive setup failed: {e}")
        except Exception as e:
            log.warn(f"{peer}: connect failed {host}:{port}: {e}")
            writer.close()
            return

        t1 = asyncio.create_task(self._pipe(reader, remote_writer, "up", uuid_got))
        t2 = asyncio.create_task(self._pipe(remote_reader, writer, "down", uuid_got))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        for w in (remote_writer, writer):
            try: w.close()
            except Exception: pass
        for w in (remote_writer, writer):
            try: await w.wait_closed()
            except Exception: pass
        log.info(f"{peer} done")

    async def _handle_udp(self, reader, writer, host, port, peer):
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            if not infos:
                return
            family, _, _, _, addr = infos[0]
            udp_sock = socket.socket(family, socket.SOCK_DGRAM)
            udp_sock.setblocking(False)
            udp_sock.connect(addr)
            writer.write(b"\x00\x00")
            await writer.drain()
            log.info(f"{peer} -> UDP {host}:{port}")
            loop = asyncio.get_event_loop()

            async def c2u():
                try:
                    while True:
                        h = await reader.readexactly(2)
                        plen = struct.unpack(">H", h)[0]
                        p = await reader.readexactly(plen)
                        await loop.sock_sendall(udp_sock, p)
                except Exception:
                    pass

            async def u2c():
                try:
                    while True:
                        d = await loop.sock_recv(udp_sock, 65536)
                        if not d:
                            break
                        writer.write(struct.pack(">H", len(d)) + d)
                        await writer.drain()
                except Exception:
                    pass

            t1 = asyncio.create_task(c2u())
            t2 = asyncio.create_task(u2c())
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in (t1, t2):
                t.cancel()
            try: udp_sock.close()
            except Exception: pass
        except Exception as e:
            log.warn(f"{peer}: UDP error: {e}")
        finally:
            try: writer.close()
            except Exception: pass

    async def _read_vless_header(self, reader):
        try:
            first = await reader.readexactly(18)
        except asyncio.IncompleteReadError:
            return None
        version = first[0]
        if version != VERSION:
            return None
        uuid_got = first[1:17]
        opt_len = first[17]
        addons = b""
        if opt_len > 0:
            try:
                addons = await reader.readexactly(opt_len)
            except asyncio.IncompleteReadError:
                return None

        # Диагностика: показать Addons
        if opt_len > 0:
            log.debug(f"[vless] Addons ({opt_len}): {addons[:40]!r}")
        else:
            log.debug("[vless] opt_len=0 (нет Addons)")

        # Парсим Addons для flow
        flow = ""
        if addons and len(addons) >= 2:
            # Простой парсер: ищем строку "xtls-rprx-vision"
            try:
                # В Xray Addons это protobuf, но flow обычно в виде строки
                text = addons.decode("utf-8", errors="ignore")
                if "xtls-rprx-vision" in text:
                    flow = "xtls-rprx-vision"
            except Exception:
                pass
        
        # Сохраняем flow в reader для wrap_server
        reader._vless_flow = flow
        try:
            rest = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return None
        cmd = rest[0]
        port = struct.unpack(">H", rest[1:3])[0]
        atyp = rest[3]

        if atyp == ATYP_IPV4:
            try:
                raw = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                return None
            host = socket.inet_ntoa(raw)
        elif atyp == ATYP_DOMAIN:
            try:
                dlen = (await reader.readexactly(1))[0]
                raw = await reader.readexactly(dlen)
            except asyncio.IncompleteReadError:
                return None
            host = raw.decode("ascii", errors="replace")
        elif atyp == ATYP_IPV6:
            try:
                raw = await reader.readexactly(16)
            except asyncio.IncompleteReadError:
                return None
            host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            return None

        return uuid_got, cmd, host, port, flow

    async def _pipe(self, reader, writer, direction="up", uuid_bytes=None):
        idle = self.cfg.get("idle_timeout", 300)
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(65536), timeout=idle)
                except asyncio.TimeoutError:
                    log.debug("idle timeout, closing pipe")
                    break
                if not data:
                    break
                if uuid_bytes is not None:
                    if direction == "up":
                        stats.add_user_up(uuid_bytes, len(data))
                    else:
                        stats.add_user_down(uuid_bytes, len(data))
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try: writer.close()
            except Exception: pass