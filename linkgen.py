# linkgen.py
import sys
import base64
import urllib.parse

from genconf import load_config


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def generate_link(cfg, host, port=None, name=None, with_vision=False):
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

    if with_vision:
        params.append(("flow", "xtls-rprx-vision"))

    qs = urllib.parse.urlencode(params)
    frag = urllib.parse.quote(name, safe="")
    return f"vless://{uuid}@{host}:{port}?{qs}#{frag}"


def print_qr(text):
    try:
        import qrcode
    except ImportError:
        print("[!] pip install qrcode")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def print_components(cfg, host, port):
    print("=== components ===")
    print(f"  uuid        = {cfg['uuid']}")
    print(f"  host        = {host}")
    print(f"  port        = {port}")
    print(f"  public_key  = {cfg['public_key']}")
    print(f"  pbk         = {b64url_nopad(bytes.fromhex(cfg['public_key']))}")
    print(f"  short_id    = {cfg['short_id']}")
    print(f"  sni         = {cfg['dest'].rsplit(':', 1)[0]}")
    print(f"  dest        = {cfg['dest']}")


def main():
    cfg = load_config(noconfig=False)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]

    host = args[0] if len(args) > 0 else "127.0.0.1"
    port = int(args[1]) if len(args) > 1 else cfg.get("listen_port", 8443)
    name = args[2] if len(args) > 2 else "vless-reality"

    show_vision = "--vision" in flags
    show_no_vision = "--no-vision" in flags
    show_qr = "--qr" in flags

    def _emit(link, title):
        print(f"=== {title} ===")
        print(link)
        if show_qr:
            print()
            print_qr(link)
        print()

    if show_vision and not show_no_vision:
        link = generate_link(cfg, host, port, name, with_vision=True)
        _emit(link, "WITH VISION")
    elif show_no_vision and not show_vision:
        link = generate_link(cfg, host, port, name, with_vision=False)
        _emit(link, "NO VISION")
    else:
        _emit(generate_link(cfg, host, port, name, with_vision=False),
              "NO VISION")
        _emit(generate_link(cfg, host, port, name + "-vision", with_vision=True),
              "WITH VISION")

    print_components(cfg, host, port)


if __name__ == "__main__":
    main()
