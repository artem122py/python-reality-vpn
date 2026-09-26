# src/reality_vpn/cli/main.py
"""CLI точка входа для reality-vpn."""
import sys
import socket
import struct
import fcntl
import ipaddress
import asyncio

from reality_vpn.cli.config import load_config_file
from reality_vpn.utils.genconf import load_config
from reality_vpn.utils.log import log
from reality_vpn.server.server import VlessServer


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
        print("usage: reality-vpn server [noconfig] [--vision|--no-vision] [--debug] <addr>")
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

    # Расширенные команды
    if len(argv) >= 2 and argv[1] in ("status", "stop", "users", "link", "stats", "version", "traffic"):
        cmd = argv[1]
        rest = argv[2:]
        from reality_vpn.cli.commands import (
            cmd_status, cmd_stop, cmd_users, cmd_link,
            cmd_stats, cmd_version, cmd_traffic,
        )
        if cmd == "status":
            cmd_status()
        elif cmd == "stop":
            cmd_stop()
        elif cmd == "users":
            cmd_users(rest)
        elif cmd == "link":
            cmd_link(rest[0] if len(rest) > 0 else None,
                     rest[1] if len(rest) > 1 else None,
                     rest[2] if len(rest) > 2 else None,
                     with_vision=("--vision" in rest))
        elif cmd == "stats":
            cmd_stats()
        elif cmd == "version":
            cmd_version()
        elif cmd == "traffic":
            cmd_traffic()
        return

    mode, noconfig, addr = parse_args(argv)

    # Загружаем конфиг
    if noconfig:
        cfg = load_config(noconfig)
    else:
        try:
            cfg = load_config_file()
        except FileNotFoundError:
            cfg = load_config(noconfig)

    if mode == "server":
        # CLI-флаги поверх конфига
        if "--vision" in argv:
            cfg["use_vision"] = True
            cfg["vision_debug"] = True
            print("[*] Vision: ON (CLI)")
        if "--no-vision" in argv:
            cfg["use_vision"] = False
            print("[*] Vision: OFF (CLI)")
        if "--debug" in argv:
            cfg["debug"] = True
            print("[*] Debug: ON (CLI)")

        log.configure(
            debug=cfg.get("debug", False),
            log_file=cfg.get("log_file") or None,
        )
        print_addresses(addr)
        print(f"[*] use_vision = {cfg.get('use_vision', False)}")

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
