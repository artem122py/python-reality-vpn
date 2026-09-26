# server.py
import asyncio
import signal
import struct
import socket
import uuid as uuidlib

from reality_vpn.core.tls13 import wrap_server
from reality_vpn.utils.stats import stats
from reality_vpn.utils.guard import guard
from reality_vpn.utils.traffic import limiter
from reality_vpn.utils.log import log
from reality_vpn.utils.linkgen import generate_link


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

SERVER_VERSION = "2.1.0"
BUILD_DATE = "2026-09-26"
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x02
ATYP_IPV6 = 0x03


def _parse_vless_addons(addons: bytes) -> dict:
    """Protobuf-парсер VLESS Addons. Поле flow — строка xtls-*."""
    out = {"flow": "", "seed": b""}
    i = 0
    n = len(addons)
    while i < n:
        tag = addons[i]; i += 1
        wire = tag & 0x07
        if wire == 0:
            while i < n and (addons[i] & 0x80):
                i += 1
            i += 1
            continue
        if wire != 2:
            break
        ln = addons[i]; i += 1
        if ln & 0x80:
            shift = 7
            ln &= 0x7f
            while i < n:
                b = addons[i]; i += 1
                ln |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
        if i + ln > n:
            break
        val = addons[i:i+ln]; i += ln
        try:
            txt = val.decode("ascii")
        except Exception:
            continue
        if txt.startswith("xtls-"):
            out["flow"] = txt
    return out


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


        # Загружаем статистику
        stats.load()
        stats.load_user_map(self.cfg)
        log.info(f"[stats] loaded: {len(stats.users)} user(s)")

        # Загружаем лимиты трафика
        limiter.load(self.cfg)
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
                    from reality_vpn.utils.guard import guard
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

        if len(hdr) == 6:
            uuid_got, cmd, host, port, flow, xudp_frame = hdr
        else:
            uuid_got, cmd, host, port, flow = hdr
            xudp_frame = None

        if uuid_got not in self.valid_uuids:
            log.warn(f"{peer}: uuid mismatch")
            if not is_local_ip(peer):
                guard.record_attempt(peer[0] if peer else "?")
            return

        # Проверяем лимит трафика
        if not limiter.check(uuid_got, stats):
            log.warn(f"{peer}: traffic limit exceeded")
            return

        # Per-user: отметить подключение
        stats.on_user_connect(uuid_got)

        if cmd == CMD_UDP:
            await self._handle_udp(reader, writer, host, port, peer,
                                    uuid_got=uuid_got,
                                    initial_frame=xudp_frame)
            return
        if cmd == CMD_MUX:
            log.debug(f"{peer}: Mux not implemented")
            return
        if cmd != CMD_TCP:
            log.debug(f"{peer}: unknown command {cmd}")
            return

        # XTLS-Vision — включаем ДО VLESS-ответа
        if flow == "xtls-rprx-vision" and self.cfg.get("use_vision", False):
            try:
                from reality_vpn.server.vision import enable_vision_after_header
                log.info(f"[vision] enabling (flow={flow!r})")
                reader, writer = await enable_vision_after_header(
                    reader, writer, uuid_got, self.cfg,
                )
            except Exception as e:
                log.error(f"[vision] enable failed: {type(e).__name__}: {e}")

        writer.write(b"\x00\x00")
        await writer.drain()

        # XTLS-Vision — включается ПОСЛЕ VLESS-заголовка
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

    async def _handle_udp(self, reader, writer, host, port, peer,
                          uuid_got=None, initial_frame=None):
        """XUDP-обработчик: один фрейм → один UDP-запрос → ответ.

        Happ использует XUDP через одноразовые TCP-соединения,
        поэтому отвечаем СИНХРОННО на каждый фрейм.
        """
        if initial_frame is None:
            return await self._handle_udp_legacy(reader, writer, host, port, peer)

        loop = asyncio.get_event_loop()
        sessions = {}  # id -> (sock, host, port)
        stop = asyncio.Event()

        async def send_udp(frame):
            mux_id = frame["id"]
            sess = sessions.get(mux_id)
            if sess is None:
                try:
                    infos = await loop.getaddrinfo(
                        frame["host"], frame["port"],
                        type=socket.SOCK_DGRAM)
                    fam, _, _, _, sa = infos[0]
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setblocking(False)
                    sock.connect(sa)
                    sess = (sock, frame["host"], frame["port"])
                    sessions[mux_id] = sess
                except Exception as e:
                    log.debug(f"[udp] id={mux_id} resolve fail: {e}")
                    return
            sock, fhost, fport = sess
            try:
                await loop.sock_sendall(sock, frame["data"])
            except Exception as e:
                log.debug(f"[udp] id={mux_id} send fail: {e}")

        async def recv_and_reply(mux_id):
            sess = sessions.get(mux_id)
            if sess is None:
                return
            sock, fhost, fport = sess
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 65536), timeout=2.0)
            except asyncio.TimeoutError:
                log.debug(f"[udp] id={mux_id} recv timeout")
                return
            except Exception as e:
                log.debug(f"[udp] id={mux_id} recv fail: {e}")
                return
            if not data:
                return
            try:
                pkt = self._build_xudp_frame(
                    uuid_got, mux_id, fhost, fport, data)
                writer.write(pkt)
                await writer.drain()
            except Exception as e:
                log.debug(f"[udp] id={mux_id} reply fail: {e}")

        async def process_frame(frame):
            await send_udp(frame)
            await recv_and_reply(frame["id"])

        async def reader_loop():
            # Первый фрейм
            try:
                await process_frame(initial_frame)
            except Exception as e:
                log.warn(f"[udp] initial frame: {e}")
            # Дальше
            while not stop.is_set():
                try:
                    frame = await self._read_xudp_from_reader(reader)
                except Exception as e:
                    log.warn(f"[udp] reader exc: {type(e).__name__}: {e}")
                    break
                if frame is None:
                    break
                try:
                    await process_frame(frame)
                except Exception as e:
                    log.warn(f"[udp] process exc: {e}")
                    break
            stop.set()

        await reader_loop()

        # Закрываем сокеты
        for sess in sessions.values():
            try: sess[0].close()
            except Exception: pass

    async def _handle_udp_legacy(self, reader, writer, host, port, peer):
        """Старый VLESS UDP (без XUDP): [len(2)][payload]."""
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            family, _, _, _, sockaddr = infos[0]
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setblocking(False)
            udp_sock.connect(sockaddr)
        except Exception as e:
            log.debug(f"[udp] legacy resolve fail: {e}")
            return
        try:
            writer.write(b"\x00\x00")
            await writer.drain()
            stop = asyncio.Event()
            idle = self.cfg.get("idle_timeout", 300)

            async def c2u():
                while not stop.is_set():
                    try:
                        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=idle)
                        plen = struct.unpack(">H", hdr)[0]
                        payload = await asyncio.wait_for(reader.readexactly(plen), timeout=5)
                        await loop.sock_sendall(udp_sock, payload)
                    except Exception:
                        break
                stop.set()

            async def u2c():
                while not stop.is_set():
                    try:
                        data = await asyncio.wait_for(loop.sock_recv(udp_sock, 65536), timeout=idle)
                        writer.write(struct.pack(">H", len(data)) + data)
                        await writer.drain()
                    except Exception:
                        break
                stop.set()

            t1 = asyncio.create_task(c2u())
            t2 = asyncio.create_task(u2c())
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in (t1, t2):
                t.cancel()
        finally:
            try: udp_sock.close()
            except Exception: pass

    async def _read_vless_header(self, reader):
        try:
            first = await reader.readexactly(18)
        except asyncio.IncompleteReadError:
            log.debug("[vless] HEADER FAIL: readexactly(18) incomplete")
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

        if opt_len > 0:
            log.debug(f"[vless] Addons ({opt_len}): {addons[:40]!r}")
        else:
            log.debug("[vless] opt_len=0 (нет Addons)")

        flow = ""
        if addons and len(addons) >= 2:
            try:
                flow = _parse_vless_addons(addons).get("flow", "")
            except Exception as e:
                log.debug(f"[vless] addons parse error: {e}")

        try:
            rest = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return None

        cmd = rest[0]
        port = struct.unpack(">H", rest[1:3])[0]
        atyp = rest[3]

        # ---- XUDP / Mux.Cool (cmd=0x03) ----
        if cmd == 0x03:
            return await self._read_xudp_frame(reader, uuid_got, flow, rest)

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

        return uuid_got, cmd, host, port, flow, None

    def _build_xudp_frame(self, uuid_bytes, mux_id, host, port, udp_payload):
        """Ответный XUDP-фрейм (Keep, без GID).

        [ID:2][Status:0x02][Opt:0x01][N:0x02][Port:2][T:1][Addr][len:2][Data]
        """
        inner = bytearray()
        inner += struct.pack(">H", mux_id)
        inner.append(0x02)   # Status = Keep
        inner.append(0x01)   # Opt = Data
        inner.append(0x02)   # N = UDP
        inner += struct.pack(">H", port)
        try:
            ip = socket.inet_aton(host)
            inner.append(0x01)
            inner += ip
        except OSError:
            hb = host.encode("ascii")
            inner.append(0x02)
            inner.append(len(hb))
            inner += hb
        inner += struct.pack(">H", len(udp_payload))
        inner += udp_payload

        pkt = bytearray()
        pkt += uuid_bytes[:16]
        pkt.append(0x00)
        pkt += struct.pack(">H", len(inner))
        pkt += struct.pack(">H", 0)
        pkt += inner
        return bytes(pkt)

    async def _read_xudp_frame(self, reader, uuid_got, flow, rest):
        """XUDP-фрейм от Happ (Vision-конверт внутри cmd=0x03).

        Формат data (после Vision-разбора):
          [ID:2][reserved:5 = 00 00 01 01 02][port:2][T:1][addr]
          [GlobalID:8 — только для New]
          [len:2][udp_payload len]
        """
        try:
            # Дочитываем остаток UUID (13) + Vision cmd(1) + clen(2) + plen(2) = 18
            more = await reader.readexactly(18)
            uuid_full = bytes(rest[1:4]) + bytes(more[0:13])
            inner_cmd = more[13]
            inner_clen = struct.unpack(">H", more[14:16])[0]
            inner_plen = struct.unpack(">H", more[16:18])[0]

            payload = await reader.readexactly(inner_clen)
            if inner_plen > 0:
                await reader.readexactly(inner_plen)

            # Проверим, что data начинается с [00 XX 00 00 01 01 02]
            if len(payload) < 10:
                log.warn(f"[mux] data too short: {payload.hex()}")
                return None

            # Парсим XUDP-фрейм
            frame = self._parse_xudp_data(payload)
            if frame is None:
                return None


            # Возвращаем: cmd=0x02 (UDP), host, port, и в data кладём UDP-payload
            # Но _handle_udp ожидает [len(2)][payload] — обернём
            return uuid_got, 0x02, frame["host"], frame["port"], flow, frame

        except asyncio.IncompleteReadError:
            log.debug("[mux] readexactly incomplete")
            return None

    def _parse_xudp_data(self, data: bytes):
        """Разбор XUDP data.

        [ID:2][00 00 01 01 02:5][port:2][T:1][addr...][GlobalID:8?][len:2][payload]
        """
        try:
            pos = 0
            mux_id = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
            # 5 байт reserved: 00 00 01 01 02
            reserved = data[pos:pos+5]; pos += 5
            if reserved != b"\x00\x00\x01\x01\x02":
                log.warn(f"[mux] reserved mismatch: {reserved.hex()}")
                # всё равно продолжаем
            port = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
            t = data[pos]; pos += 1

            if t == 0x01:
                addr = data[pos:pos+4]; pos += 4
                host = socket.inet_ntoa(addr)
            elif t == 0x02:
                dlen = data[pos]; pos += 1
                addr = data[pos:pos+dlen]; pos += dlen
                host = addr.decode("ascii", "replace")
            elif t == 0x03:
                addr = data[pos:pos+16]; pos += 16
                host = socket.inet_ntop(socket.AF_INET6, addr)
            else:
                log.warn(f"[mux] unknown T=0x{t:02x}")
                return None

            # Попробуем определить, есть ли GlobalID.
            # Если после addr идут 8 случайных байт, потом len — New.
            # Если сразу len (2 байта, старший = 0x00) — Keep.
            gid = None
            if pos + 10 <= len(data):
                maybe_len_new = struct.unpack(">H", data[pos+8:pos+10])[0]
                maybe_len_keep = struct.unpack(">H", data[pos:pos+2])[0]
                # Эвристика: если keep-len совпадает с оставшейся длиной → Keep
                if maybe_len_keep == len(data) - pos - 2:
                    gid = None
                elif maybe_len_new == len(data) - pos - 10:
                    gid = data[pos:pos+8]; pos += 8
                else:
                    # По умолчанию — New
                    gid = data[pos:pos+8]; pos += 8
            else:
                gid = data[pos:pos+8]; pos += 8

            dlen = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
            payload = data[pos:pos+dlen]

            return {"id": mux_id, "host": host, "port": port, "t": t,
                    "gid": gid, "data": payload}
        except Exception as e:
            log.debug(f"[mux] parse error: {type(e).__name__}: {e}")
            return None

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