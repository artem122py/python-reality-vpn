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



VERSION = 0x00
CMD_TCP = 0x01
CMD_UDP = 0x02
CMD_MUX = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x02
ATYP_IPV6 = 0x03


class VlessServer:
    def __init__(self, cfg, addr):
        self.cfg = cfg
        self.addr = addr
        self.uuid_bytes = uuidlib.UUID(cfg["uuid"]).bytes
        self.port = cfg.get("listen_port", 8443)
        self.one_shot = False
        self._done = asyncio.Event()

    async def run(self):
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

        display_host = self._pick_display_host()
        try:
            link = generate_link(self.cfg, display_host, self.port)
            log.info(f"VLESS Link: {link}")
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
            serve_task.cancel()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass
            log.info(f"[stats] final: {stats.summary()}")


    async def _stats_loop(self):
        interval = self.cfg.get("stats_interval", 60)
        counter = 0
        while True:
            await asyncio.sleep(interval)
            log.info(f"[stats] {stats.summary()}")
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

        # Rate limiting
        if guard.is_banned(ip):
            log.info(f"{peer}: BANNED (rate limit)")
            try: writer.close()
            except Exception: pass
            return

        if guard.record_attempt(ip):
            log.warn(f"{peer}: rate limit exceeded → banned for 5m")
            stats.on_handshake_fail()
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
            log.debug(f"{peer}: bad header")
            return

        uuid_got, cmd, host, port = hdr

        if uuid_got != self.uuid_bytes:
            log.warn(f"{peer}: uuid mismatch")
            return

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
        log.info(f"{peer} -> {host}:{port}")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            log.warn(f"{peer}: connect failed {host}:{port}: {e}")
            writer.close()
            return

        t1 = asyncio.create_task(self._pipe(reader, remote_writer))
        t2 = asyncio.create_task(self._pipe(remote_reader, writer))
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
        if opt_len > 0:
            try:
                await reader.readexactly(opt_len)
            except asyncio.IncompleteReadError:
                return None
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

        return uuid_got, cmd, host, port

    async def _pipe(self, reader, writer):
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
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try: writer.close()
            except Exception: pass