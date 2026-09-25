import time
from reality_vpn.utils.guard import RateLimiter


def test_no_ban_below_limit():
    g = RateLimiter(max_attempts=5, window=60, ban_time=60)
    for _ in range(4):
        assert g.record_attempt("1.2.3.4") is False
    assert g.is_banned("1.2.3.4") is False


def test_ban_after_limit():
    g = RateLimiter(max_attempts=3, window=60, ban_time=60)
    assert g.record_attempt("1.2.3.4") is False
    assert g.record_attempt("1.2.3.4") is False
    assert g.record_attempt("1.2.3.4") is False
    # 4-я попытка превышает лимит
    assert g.record_attempt("1.2.3.4") is True
    assert g.is_banned("1.2.3.4") is True


def test_different_ips_independent():
    g = RateLimiter(max_attempts=2, window=60, ban_time=60)
    g.record_attempt("1.1.1.1")
    g.record_attempt("1.1.1.1")
    assert g.record_attempt("1.1.1.1") is True
    # Другой IP не забанен
    assert g.is_banned("2.2.2.2") is False


def test_ban_expires():
    g = RateLimiter(max_attempts=1, window=60, ban_time=0.1)
    g.record_attempt("1.2.3.4")
    g.record_attempt("1.2.3.4")
    assert g.is_banned("1.2.3.4") is True

    time.sleep(0.2)
    assert g.is_banned("1.2.3.4") is False
