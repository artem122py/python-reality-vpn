# vision.py — XTLS-Vision (XTLS-RPRX-Vision) для VLESS+Reality
"""
Реализация vision-flow из Xray-core (упрощённо, но с корректным форматом).

Формат padding-пакета:
  UUID:        16 байт   ← ТОЛЬКО в первом исходящем пакете
  Command:     1 байт    ← 0=Continue, 1=End, 2=Direct
  ContentLen:  2 байта BE
  PaddingLen:  2 байта BE
  Content:     ContentLen байт
  Padding:     PaddingLen байт

Long padding (contentLen < 900): общий размер пакета = 900..1400 байт
Short padding (contentLen >= 900): padding 0..256 байт

State machine:
  - INIT: ждём первый байт
  - FILTERING: разбираем padding-пакеты
  - DIRECT: passthrough
"""
import os
import struct
import asyncio
from vpnlog import log


UUID_LEN = 16
HDR_WITH_UUID = 21          # UUID(16) + cmd(1) + clen(2) + plen(2)
HDR_NO_UUID = 5             # cmd(1) + clen(2) + plen(2)

CMD_CONTINUE = 0
CMD_END = 1
CMD_DIRECT = 2

LONG_PADDING_THRESHOLD = 900
LONG_PADDING_MAX = 1400

ST_INIT = "init"
ST_FILTERING = "filtering"
ST_DIRECT = "direct"


def is_tls_handshake(data):
    """Первый байт TLS record — 0x16 (Handshake)."""
    return len(data) >= 1 and data[0] == 0x16


def make_packet(uuid, command, content, include_uuid, is_uplink=False, long_padding=False):
    """
    Собирает padding-пакет. Правила Xray:
      - Long padding (для TLS handshake): contentLen < 900 → общий размер 900..1400
      - Short padding (обычные данные):
          uplink: contentLen < 100 → padding 0..256
          downlink: contentLen < 256 → padding 0..256
      - Иначе — без padding
    Padding — нулевые байты (как buf.Extend в Go).
    """
    clen = len(content)
    plen = 0

    if long_padding:
        if clen < 900:
            plen = int.from_bytes(os.urandom(2), "big") % 500 + 900 - clen
    else:
        if is_uplink:
            if clen < 100:
                plen = os.urandom(1)[0]
        else:
            if clen < 256:
                plen = os.urandom(1)[0]

    if plen < 0:
        plen = 0

    out = bytearray()
    if include_uuid:
        out += uuid
    out.append(command)
    out += struct.pack(">H", clen)
    out += struct.pack(">H", plen)
    out += content
    out += b"\x00" * plen       # padding = нули, не случайные
    return bytes(out)



class PacketParser:
    """Парсер входящего padding-потока."""

    def __init__(self, uuid, debug=False):
        self.uuid = uuid
        self.debug = debug
        self.buf = b""
        self.expect_uuid = True
        self.finished = False  # True после Command=End|Direct

    def _log(self, msg):
        if self.debug:
            log.debug(f"[vision-parse] {msg}")

    def feed(self, data):
        """Добавляет данные в буфер."""
        self.buf += data

    def try_parse(self):
        """
        Возвращает (content, command) или None, если данных мало.
        Если UUID не совпал — возвращает спец-маркер ('direct', None).
        """
        if self.finished:
            return None

        head = HDR_WITH_UUID if self.expect_uuid else HDR_NO_UUID
        if len(self.buf) < head:
            return None

        pos = 0
        if self.expect_uuid:
            if self.buf[:UUID_LEN] != self.uuid:
                self._log("uuid mismatch → direct")
                self.finished = True
                return ("direct", None)
            pos = UUID_LEN

        command = self.buf[pos]
        clen = struct.unpack(">H", self.buf[pos + 1:pos + 3])[0]
        plen = struct.unpack(">H", self.buf[pos + 3:pos + 5])[0]
        pos += 5

        total = pos + clen + plen
        if len(self.buf) < total:
            return None

        content = self.buf[pos:pos + clen]
        self.buf = self.buf[total:]

        if self.expect_uuid:
            self.expect_uuid = False

        self._log(f"pkt cmd={command} clen={clen} plen={plen} left={len(self.buf)}")

        if command in (CMD_END, CMD_DIRECT):
            self.finished = True

        return content, command


def build_first_packet(uuid, content, debug=False):
    """Первый исходящий padding-пакет: UUID + cmd=Direct + content + padding."""
    pkt = make_packet(uuid, CMD_DIRECT, content, include_uuid=True)
    if debug:
        log.debug(f"[vision-build] first pkt: content={len(content)} total={len(pkt)}")
    return pkt


async def read_vision_packet(reader, uuid, debug=False):
    """
    Читает ОДИН padding-пакет из reader. Возвращает (content, command) или (None, None).
    Используется для чтения первого padding-пакета от клиента.
    """
    parser = PacketParser(uuid, debug=debug)
    for _ in range(100):  # максимум 100 итераций
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=10.0)
        except asyncio.TimeoutError:
            if debug:
                log.debug("[vision] read timeout")
            return None, None

        if not data:
            if debug:
                log.debug("[vision] EOF")
            return None, None

        parser.feed(data)
        result = parser.try_parse()
        if result is not None:
            content, command = result
            # Если остались данные после пакета — вернём их тоже
            return content, command, parser.buf

    return None, None, b""


class VisionStreamReader:
    """Reader-обёртка: парсит padding, возвращает чистый content."""

    def __init__(self, reader, uuid, debug=False):
        self.reader = reader
        self.uuid = uuid
        self.debug = debug
        self.parser = PacketParser(uuid, debug=debug)
        self.out = b""

    def _log(self, msg):
        if self.debug:
            log.debug(f"[vision-r] {msg}")

    async def read(self, n=65536):
        if not hasattr(self, "_first_read_done"):
            self._first_read_done = True
            log.debug(f"[vision-r] FIRST read (parser.finished={self.parser.finished})")
        while len(self.out) < n:
            if not self.parser.finished:
                # Пытаемся распарсить накопленный буфер
                while True:
                    result = self.parser.try_parse()
                    if result is None:
                        break
                    content, cmd = result
                    if content == "direct":
                        # UUID не совпал — переходим в direct, отдаём всё что есть
                        self.out += self.parser.buf
                        self.parser.buf = b""
                        break
                    self.out += content

                if not self.parser.finished:
                    try:
                        data = await self.reader.read(65536)
                    except Exception as e:
                        self._log(f"read err: {e}")
                        break
                    if not data:
                        break
                    self.parser.feed(data)
                    continue
                else:
                    # finished — остаток отдаём как direct данные
                    if self.parser.buf:
                        self.out += self.parser.buf
                        self.parser.buf = b""
            else:
                # direct
                try:
                    data = await self.reader.read(65536)
                except Exception as e:
                    self._log(f"read err: {e}")
                    break
                if not data:
                    break
                self.out += data

        out = self.out[:n]
        self.out = self.out[n:]
        return out

    async def readexactly(self, n):
        while len(self.out) < n:
            data = await self.read(n)
            if not data and len(self.out) < n:
                raise asyncio.IncompleteReadError(self.out, n)
        out = self.out[:n]
        self.out = self.out[n:]
        return out


class VisionStreamWriter:
    """Writer-обёртка: первый write оборачивает в padding-пакет."""

    def __init__(self, writer, uuid, debug=False):
        self.writer = writer
        self.uuid = uuid
        self.debug = debug
        self.first_done = False

    def send_initial_padding(self):
        """
        Отправляет короткий padding-пакет с Command=Direct.
        Downlink, contentLen=0, padding 0..255.
        """
        if self.first_done:
            return
        # Первый пакет — LONG padding (как Xray для TLS handshake)
        pkt = make_packet(
            self.uuid, CMD_DIRECT, b"",
            include_uuid=True,
            is_uplink=False,
            long_padding=True,
        )
        log.debug(f"[vision-w] initial padding: total={len(pkt)} bytes")
        self.writer.write(pkt)
        self.first_done = True

    def _log(self, msg):
        if self.debug:
            log.debug(f"[vision-w] {msg}")

    def write(self, data):
        if not data:
            return
        is_tls = len(data) >= 1 and data[0] == 0x16
        long_pad = is_tls

        if not self.first_done:
            pkt = make_packet(
                self.uuid, CMD_DIRECT, data,
                include_uuid=True,
                is_uplink=False,
                long_padding=long_pad,
            )
            log.debug(f"[vision-w] FIRST pkt: content={len(data)} total={len(pkt)} tls={is_tls}")
            self.writer.write(pkt)
            self.first_done = True
        else:
            # после CMD_DIRECT — passthrough по Xray-спеке
            self.writer.write(data)

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return self.writer.get_extra_info(name, default)


async def enable_vision_after_header(reader, writer, uuid_bytes, cfg):
    """
    Включает Vision ПОСЛЕ чтения VLESS-заголовка.

    Возвращает обёрнутые reader/writer (Vision).
    Reader — читает padding от клиента (начнёт с direct если padding не обнаружен).
    Writer — оборачивает первый write в padding-пакет.
    """
    debug = cfg.get("vision_debug", False)

    if debug:
        log.debug("[vision] enable_vision_after_header CALLED")

    vreader = VisionStreamReader(reader, uuid_bytes, debug=debug)
    vwriter = VisionStreamWriter(writer, uuid_bytes, debug=debug)

    # Сразу отправляем padding от сервера, чтобы клиент не таймаутил
    try:
        vwriter.send_initial_padding()
    except Exception as e:
        log.error(f"[vision] send_initial_padding failed: {e}")

    return vreader, vwriter


