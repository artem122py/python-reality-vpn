# testClient.py — простой VLESS-клиент (без TLS), для отладки
"""
Использование:
    python testClient.py [server_host] [server_port] [target_host] [target_port]

Примеры:
    python testClient.py
        → 127.0.0.1:8443 -> example.com:80, GET /

    python testClient.py 127.0.0.1 8443 ya.ru 443
        → 127.0.0.1:8443 -> ya.ru:443, GET /

    python testClient.py 127.0.0.1 8443 httpbin.org 80
        → 127.0.0.1:8443 -> httpbin.org:80, GET /get

Переменные окружения:
    VLESS_TARGET_HOST — target host
    VLESS_TARGET_PORT — target port
    VLESS_REQUEST_PATH — путь для GET (по умолчанию /)
"""
import asyncio
import json
import socket
import struct
import sys
import os
import uuid as uuidlib


VERSION = 0x00
CMD_TCP = 0x01
ATYP_DOMAIN = 0x02
ATYP_IPV4 = 0x01
ATYP_IPV6 = 0x03


def load_cfg():
    with open("config.json") as f:
        return json.load(f)


def build_vless_header(uuid_str, host, port):
    out = bytearray()
    out.append(VERSION)
    out += uuidlib.UUID(uuid_str).bytes
    out.append(0x00)                    # opt_len
    out.append(CMD_TCP)
    out += struct.pack(">H", port)

    # IPv4
    try:
        socket.inet_aton(host)
        out.append(ATYP_IPV4)
        out += socket.inet_aton(host)
        return bytes(out)
    except OSError:
        pass

    # IPv6
    if ":" in host:
        try:
            out.append(ATYP_IPV6)
            out += socket.inet_pton(socket.AF_INET6, host)
            return bytes(out)
        except OSError:
            pass

    # Domain
    out.append(ATYP_DOMAIN)
    hb = host.encode("idna")
    out.append(len(hb))
    out += hb
    return bytes(out)


def build_request(host, path="/"):
    """Простой HTTP/1.0 запрос."""
    return (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")


async def run_client(server_host, server_port,
                     target_host, target_port,
                     path="/"):
    cfg = load_cfg()
    uuid_str = cfg["uuid"]

    print(f"[*] connecting to {server_host}:{server_port} (plain TCP)")
    try:
        reader, writer = await asyncio.open_connection(server_host, server_port)
    except Exception as e:
        print(f"[!] connect failed: {e}")
        return

    hdr = build_vless_header(uuid_str, target_host, target_port)
    print(f"[*] VLESS header: {hdr.hex()}")
    writer.write(hdr)
    await writer.drain()

    try:
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=5)
    except asyncio.TimeoutError:
        print("[!] timeout waiting for VLESS response")
        writer.close()
        return

    if resp != b"\x00\x00":
        print(f"[!] bad VLESS response: {resp.hex()}")
        writer.close()
        return

    print(f"[*] VLESS accepted, requesting {target_host}:{target_port}{path}")

    request = build_request(target_host, path)
    writer.write(request)
    await writer.drain()

    print("[*] response:")
    print("-" * 60)
    total = 0
    try:
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            if not data:
                break
            total += len(data)
            try:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except Exception:
                pass
    except asyncio.TimeoutError:
        print("\n[!] timeout waiting for data")
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
    args = sys.argv[1:]

    # Дефолты
    server_host = "127.0.0.1"
    server_port = 8443
    target_host = os.environ.get("VLESS_TARGET_HOST", "example.com")
    target_port = int(os.environ.get("VLESS_TARGET_PORT", "80"))
    path = os.environ.get("VLESS_REQUEST_PATH", "/")

    # Парсинг позиционных
    if len(args) > 0:
        server_host = args[0]
    if len(args) > 1:
        server_port = int(args[1])
    if len(args) > 2:
        target_host = args[2]
    if len(args) > 3:
        target_port = int(args[3])
    if len(args) > 4:
        path = args[4]

    # Хелп
    if "--help" in args or "-h" in args:
        print(__doc__)
        print("Defaults:")
        print(f"  server      = {server_host}:{server_port}")
        print(f"  target      = {target_host}:{target_port}{path}")
        return

    asyncio.run(run_client(server_host, server_port,
                            target_host, target_port, path))


if __name__ == "__main__":
    main()
