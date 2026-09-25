# testClient.py
import asyncio
import json
import socket
import struct
import ssl
import uuid as uuidlib
import sys


VERSION = 0x00
CMD_TCP = 0x01
ATYP_DOMAIN = 0x02
ATYP_IPV4 = 0x01


def load_cfg():
    with open("config.json") as f:
        return json.load(f)


def build_vless_header(uuid_str: str, host: str, port: int) -> bytes:
    out = bytearray()
    out.append(VERSION)
    out += uuidlib.UUID(uuid_str).bytes
    out.append(0x00)
    out.append(CMD_TCP)
    out += struct.pack(">H", port)

    try:
        socket.inet_aton(host)
        out.append(ATYP_IPV4)
        out += socket.inet_aton(host)
    except OSError:
        out.append(ATYP_DOMAIN)
        hbytes = host.encode("idna")
        out.append(len(hbytes))
        out += hbytes

    return bytes(out)


def make_ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Наш сервер пока умеет только TLS 1.3
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


async def run_client(server_host: str, server_port: int,
                     target_host: str, target_port: int,
                     request: bytes):
    cfg = load_cfg()
    uuid_str = cfg["uuid"]

    print(f"[*] connecting to {server_host}:{server_port} (TLS 1.3)")
    ctx = make_ssl_ctx()
    reader, writer = await asyncio.open_connection(
        server_host, server_port, ssl=ctx, server_hostname="localhost",
    )

    # Проверим, что TLS-сессия действительно установилась
    sslobj = writer.get_extra_info("ssl_object")
    if sslobj:
        print(f"[*] TLS: {sslobj.version()} / {sslobj.cipher()[0]}")

    hdr = build_vless_header(uuid_str, target_host, target_port)
    print(f"[*] VLESS header: {hdr.hex()}")
    writer.write(hdr)
    await writer.drain()

    resp = await reader.readexactly(2)
    if resp != b"\x00\x00":
        print(f"[!] bad VLESS response: {resp.hex()}")
        writer.close()
        return

    print(f"[*] VLESS accepted, sending request to {target_host}:{target_port}")
    writer.write(request)
    await writer.drain()

    print("[*] response:")
    print("-" * 60)
    total = 0
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            total += len(data)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except asyncio.IncompleteReadError:
        pass
    print()
    print("-" * 60)
    print(f"[*] received {total} bytes")

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


def main():
    server_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443

    target_host = "example.com"
    target_port = 80
    request = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"

    asyncio.run(run_client(server_host, server_port,
                           target_host, target_port, request))


if __name__ == "__main__":
    main()