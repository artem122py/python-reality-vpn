import struct
import uuid as uuidlib
from server import VlessServer, VERSION, CMD_TCP, ATYP_DOMAIN


class FakeReader:
    """Эмулирует asyncio.StreamReader для теста _read_vless_header."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    async def readexactly(self, n):
        if self.pos + n > len(self.data):
            import asyncio
            raise asyncio.IncompleteReadError(self.data[self.pos:], n)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out


def _build_header(uuid_str, host, port):
    out = bytearray()
    out.append(VERSION)
    out += uuidlib.UUID(uuid_str).bytes
    out.append(0x00)   # opt_len
    out.append(CMD_TCP)
    out += struct.pack(">H", port)
    out.append(ATYP_DOMAIN)
    h = host.encode("idna")
    out.append(len(h))
    out += h
    return bytes(out)


def test_parse_valid_header():
    uuid_str = "00000000-0000-0000-0000-000000000001"
    header = _build_header(uuid_str, "example.com", 443)

    server = VlessServer.__new__(VlessServer)
    reader = FakeReader(header)

    import asyncio
    result = asyncio.run(server._read_vless_header(reader))

    assert result is not None
    uuid_got, cmd, host, port = result
    assert cmd == CMD_TCP
    assert host == "example.com"
    assert port == 443
    assert uuid_got == uuidlib.UUID(uuid_str).bytes


def test_parse_truncated():
    uuid_str = "00000000-0000-0000-0000-000000000001"
    header = _build_header(uuid_str, "example.com", 443)[:10]  # обрезали

    server = VlessServer.__new__(VlessServer)
    reader = FakeReader(header)

    import asyncio
    result = asyncio.run(server._read_vless_header(reader))
    assert result is None


def test_parse_bad_version():
    uuid_str = "00000000-0000-0000-0000-000000000001"
    header = bytearray(_build_header(uuid_str, "example.com", 443))
    header[0] = 0xFF  # битая версия

    server = VlessServer.__new__(VlessServer)
    reader = FakeReader(bytes(header))

    import asyncio
    result = asyncio.run(server._read_vless_header(reader))
    assert result is None
