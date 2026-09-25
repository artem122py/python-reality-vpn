# linkgen.py
import sys
import base64
import urllib.parse

from genconf import load_config


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def generate_link(cfg, host, port=None, name=None):
    if port is None:
        port = cfg.get("listen_port", 8443)
    if name is None:
        name = "vless-reality"

    uuid = cfg["uuid"]
    pbk = b64url_nopad(bytes.fromhex(cfg["public_key"]))
    sid = cfg["short_id"]
    sni = cfg["dest"].rsplit(":", 1)[0]

    params = [
        ("security", "reality"),
        ("sni", sni),
        ("fp", "chrome"),
        ("pbk", pbk),
        ("sid", sid),
        ("type", "tcp"),
        ("encryption", "none"),
    ]

    qs = urllib.parse.urlencode(params)
    frag = urllib.parse.quote(name, safe="")
    return f"vless://{uuid}@{host}:{port}?{qs}#{frag}"


def print_components(cfg, host, port):
    print("=== components ===")
    print(f"  uuid        = {cfg['uuid']}")
    print(f"  host        = {host}")
    print(f"  port        = {port}")
    print(f"  public_key  = {cfg['public_key']} (hex)")
    print(f"  pbk         = {b64url_nopad(bytes.fromhex(cfg['public_key']))}")
    print(f"  short_id    = {cfg['short_id']}")
    print(f"  sni         = {cfg['dest'].rsplit(':', 1)[0]}")
    print(f"  dest        = {cfg['dest']}")


def main():
    cfg = load_config(noconfig=False)
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else cfg.get("listen_port", 8443)
    name = sys.argv[3] if len(sys.argv) > 3 else "vless-reality"

    link = generate_link(cfg, host, port, name)
    print(link)
    print()
    print_components(cfg, host, port)


if __name__ == "__main__":
    main()