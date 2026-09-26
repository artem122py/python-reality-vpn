# src/reality_vpn/server/vision.py
"""XTLS-Vision: padding для маскировки TLS-in-TLS."""
import os
import struct
import random

from reality_vpn.utils.log import log


CMD_CONTINUE = 0x00
CMD_END = 0x01
CMD_DIRECT = 0x02

LONG_MIN_CONTENT = 900
LONG_RAND = 500
LONG_TARGET = 900
SHORT_RAND = 256


class VisionState:
    def __init__(self, is_uplink):
        self.is_uplink = is_uplink
        self.direct_copy = False
        self.remaining_content = 0
        self.remaining_padding = 0
        self.current_command = CMD_CONTINUE
        self.first_packet = True


class VisionReader:
    def __init__(self, reader, state, user_uuid, leftover=b""):
        self.reader = reader
        self.state = state
        self.user_uuid = user_uuid
        self.buf = leftover or b""

    async def read(self, n=65536):
        if self.state.direct_copy:
            log.debug("[vision-r] direct_copy passthrough")
            return await self.reader.read(n)

        log.debug(f"[vision-r] read() buf={len(self.buf)}B "
                 f"rem_c={self.state.remaining_content} "
                 f"rem_p={self.state.remaining_padding} "
                 f"first={self.state.first_packet}")

        try:
            data = await self.reader.read(65536)
        except Exception as e:
            log.debug(f"[vision-r] reader.read exc: {type(e).__name__}: {e}")
            return b""

        if not data:
            return b""

        self.buf += data
        out = b""

        while len(self.buf) > 0:
            if (self.state.remaining_content == 0 and
                    self.state.remaining_padding == 0):
                need = 5
                if self.state.first_packet:
                    need += 16
                if len(self.buf) < need:
                    log.debug(f"[vision-r] need more: buf={len(self.buf)} need={need}")
                    break

                if self.state.first_packet:
                    log.info(f"[vision-r] first packet check: "
                             f"buf={len(self.buf)}B head={self.buf[:32].hex()} "
                             f"expect_uuid={self.user_uuid.hex()}")
                    uuid_got = self.buf[:16]
                    self.buf = self.buf[16:]
                    self.state.first_packet = False
                    if uuid_got != self.user_uuid:
                        log.debug("[vision-r] uuid mismatch -> direct_copy")
                        self.state.direct_copy = True
                        out += self.buf
                        self.buf = b""
                        break

                cmd = self.buf[0]
                clen = struct.unpack(">H", self.buf[1:3])[0]
                plen = struct.unpack(">H", self.buf[3:5])[0]
                log.debug(f"[vision-r] parsed cmd=0x{cmd:02x} clen={clen} plen={plen}")
                self.buf = self.buf[5:]

                self.state.current_command = cmd
                self.state.remaining_content = clen
                self.state.remaining_padding = plen

                log.debug(f"[vision-r] cmd={cmd} clen={clen} plen={plen}")

                if cmd in (CMD_DIRECT, CMD_END):
                    self.state.direct_copy = True
                    out += self.buf
                    self.buf = b""
                    break

            if self.state.remaining_content > 0:
                take = min(self.state.remaining_content, len(self.buf))
                out += self.buf[:take]
                self.buf = self.buf[take:]
                self.state.remaining_content -= take
                continue

            if self.state.remaining_padding > 0:
                take = min(self.state.remaining_padding, len(self.buf))
                self.buf = self.buf[take:]
                self.state.remaining_padding -= take
                continue

        return out

    async def readexactly(self, n):
        out = b""
        while len(out) < n:
            chunk = await self.read(n - len(out))
            if not chunk:
                break
            out += chunk
        return out


class VisionWriter:
    def __init__(self, writer, state, user_uuid, is_server=True):
        self.writer = writer
        self.state = state
        self.user_uuid = user_uuid
        self.is_server = is_server

    def write(self, data):
        if not data:
            return
        if self.state.direct_copy:
            self.writer.write(data)
            return

        is_app_data = len(data) >= 3 and data[:3] == b"\x17\x03\x03"
        # Тест: для downlink при первом не-2-байтном пакете сразу DIRECT
        if self.state.first_packet and len(data) > 2:
            cmd = CMD_DIRECT
            self.state.direct_copy = True
        else:
            cmd = CMD_DIRECT if is_app_data else CMD_CONTINUE
            if is_app_data:
                self.state.direct_copy = True
        if self.state.direct_copy:
            log.debug("[vision-w] switch to DIRECT")

        clen = len(data)
        if clen < LONG_MIN_CONTENT:
            plen = random.randint(0, LONG_RAND) + LONG_TARGET - clen
        else:
            plen = random.randint(0, SHORT_RAND)
        if plen < 0:
            plen = 0

        pkt = bytearray()
        # Серверный VisionWriter UUID НЕ отправляет — только клиент.
        uuid_in_pkt = False
        self.state.first_packet = False
        pkt += bytes([cmd])
        pkt += struct.pack(">H", clen)
        pkt += struct.pack(">H", plen)
        pkt += data
        pkt += os.urandom(plen)

        log.debug(f"[vision-w] cmd=0x{cmd:02x} clen={clen} plen={plen}")
        self.writer.write(bytes(pkt))

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return self.writer.get_extra_info(name, default)


def wrap_vision(reader, writer, user_uuid, is_server=True, leftover=b""):
    r_state = VisionState(is_uplink=True)
    w_state = VisionState(is_uplink=False)
    vr = VisionReader(reader, r_state, user_uuid, leftover=leftover)
    vw = VisionWriter(writer, w_state, user_uuid, is_server=is_server)
    return vr, vw


async def enable_vision_after_header(reader, writer, user_uuid, cfg):
    leftover = b""

    # _SecureReader (tls13.py) — расшифрованный plaintext в .buf
    if hasattr(reader, "buf") and isinstance(reader.buf, (bytes, bytearray)):
        leftover = bytes(reader.buf)
        reader.buf = b""
    # asyncio.StreamReader — сырой (зашифрованный) буфер, НЕ трогаем
    elif hasattr(reader, "_buffer"):
        log.warn("[vision] reader looks like raw StreamReader — no decrypt buffer")
    else:
        log.warn(f"[vision] unknown reader type: {type(reader).__name__}")

    log.debug(f"[vision] reader={type(reader).__name__} leftover={len(leftover)}B")

    vr, vw = wrap_vision(reader, writer, user_uuid, is_server=True,
                         leftover=leftover)

    if leftover:
        log.debug(f"[vision] leftover head: {leftover[:32].hex()}")

    return vr, vw
