# main.py
import sys
import os
import json
import socket
import struct
import fcntl
import ipaddress
import asyncio

from server import VlessServer
from genconf import load_config
from vpnlog import log


SIOCGIFADDR = 0x8915


def local_ips():
    ips = []
    for idx, name in socket.if_nameindex():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = struct.pack("256s", name[:15].encode())
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
            ip = socket.inet_ntoa(res[20:24])
            ips.append(ip)
        except OSError:
            pass
        finally:
            s.close()
    return ips


def print_addresses(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        print("Ip in Not(Is dns):")
        try:
            infos = socket.getaddrinfo(addr, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            print(f"  cannot resolve {addr}")
            return
        seen = set()
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET and sockaddr[0] not in seen:
                seen.add(sockaddr[0])
                print(f"Run in {sockaddr[0]}")
        return

    if ip.is_unspecified:
        print(f"Ip is {addr}(all):")
        ips = sorted(set(local_ips()))
        if "127.0.0.1" not in ips:
            ips.insert(0, "127.0.0.1")
        for a in ips:
            print(f"Run in {a}")
    else:
        print(f"Ip is {addr}:")
        print(f"Run in {addr}")


def parse_args(argv):
    if len(argv) < 3:
        print("usage: python main.py server [noconfig] [--once] <addr>")
        sys.exit(1)
    mode = argv[1]
    noconfig = False
    addr = None
    for a in argv[2:]:
        if a == "noconfig":
            noconfig = True
        elif a.startswith("--"):
            continue
        else:
            addr = a
    if addr is None:
        print("error: address not specified")
        sys.exit(1)
    return mode, noconfig, addr


def main():
    argv = sys.argv

    # Расширенные команды (без addr)
    if len(argv) >= 2 and argv[1] in ("status", "stop", "users", "link"):
        cmd = argv[1]
        rest = argv[2:]
        from vpncli import cmd_status, cmd_stop, cmd_users, cmd_link
        if cmd == "status":
            cmd_status()
        elif cmd == "stop":
            cmd_stop()
        elif cmd == "users":
            cmd_users(rest)
        elif cmd == "link":
            # link [name] [host] [port]
            cmd_link(rest[0] if len(rest) > 0 else None,
                     rest[1] if len(rest) > 1 else None,
                     rest[2] if len(rest) > 2 else None)
        return

    mode, noconfig, addr = parse_args(argv)
    cfg = load_config(noconfig)

    if mode == "server":
        log.configure(
            debug=cfg.get("debug", False),
            log_file=cfg.get("log_file") or None,
        )
        print_addresses(addr)
        try:
            srv = VlessServer(cfg, addr)
            if "--once" in argv:
                srv.one_shot = True
                print("[*] one_shot режим")
            asyncio.run(srv.run())
        except KeyboardInterrupt:
            print("\nshutdown")
    else:
        print(f"unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()