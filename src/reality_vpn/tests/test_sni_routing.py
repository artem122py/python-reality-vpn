from reality_vpn.core.sni_routing import SniRouter


def test_default_when_no_sni():
    r = SniRouter("ya.ru:443")
    assert r.resolve(None) == "ya.ru:443"
    assert r.resolve("") == "ya.ru:443"


def test_default_unknown_sni():
    r = SniRouter("ya.ru:443", {"google.com": "google.com:443"})
    assert r.resolve("unknown.com") == "ya.ru:443"


def test_exact_match():
    r = SniRouter("ya.ru:443", {"google.com": "google.com:443"})
    assert r.resolve("google.com") == "google.com:443"


def test_case_insensitive():
    r = SniRouter("ya.ru:443", {"google.com": "google.com:443"})
    assert r.resolve("GOOGLE.COM") == "google.com:443"
    assert r.resolve("Google.Com") == "google.com:443"


def test_wildcard():
    r = SniRouter("ya.ru:443", {"*.example.com": "example.com:443"})
    assert r.resolve("sub.example.com") == "example.com:443"
    assert r.resolve("a.b.example.com") == "example.com:443"
    assert r.resolve("example.com") == "ya.ru:443"


def test_multiple_routes():
    r = SniRouter("ya.ru:443", {
        "google.com": "google.com:443",
        "microsoft.com": "microsoft.com:443",
        "*.cloudflare.com": "cf:443",
    })
    assert r.resolve("google.com") == "google.com:443"
    assert r.resolve("microsoft.com") == "microsoft.com:443"
    assert r.resolve("api.cloudflare.com") == "cf:443"


def test_from_config():
    cfg = {
        "dest": "ya.ru:443",
        "sni_routes": {"microsoft.com": "microsoft.com:443"},
    }
    r = SniRouter.from_config(cfg)
    assert r.resolve("microsoft.com") == "microsoft.com:443"
    assert r.resolve("unknown.com") == "ya.ru:443"


def test_split_dest():
    r = SniRouter("ya.ru:443")
    assert r.split_dest("ya.ru:443") == ("ya.ru", 443)
    assert r.split_dest("ya.ru") == ("ya.ru", 443)
    assert r.split_dest("ya.ru:8443") == ("ya.ru", 8443)


def test_empty_routes():
    r = SniRouter("ya.ru:443", {})
    assert r.resolve("anything.com") == "ya.ru:443"
    assert r.resolve(None) == "ya.ru:443"
