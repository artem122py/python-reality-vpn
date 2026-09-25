from vpnlog import _Logger


def test_levels_order():
    """DEBUG < INFO < WARN < ERROR."""
    L = _Logger.LEVELS
    assert L["DEBUG"] < L["INFO"] < L["WARN"] < L["ERROR"]


def test_set_debug():
    log = _Logger()
    log.configure(debug=False)
    assert log.level == "INFO"

    log.configure(debug=True)
    assert log.level == "DEBUG"


def test_noise_filter():
    """IncompleteReadError не логируется как ERROR."""
    log = _Logger()
    log.configure(debug=False)

    # Должно молча проглотить
    log.error("[sslfork] handshake failed: IncompleteReadError: 0 bytes")
    # Не должно упасть
    log.info("normal message")


def test_color_codes():
    assert "\033" in _Logger.COLORS["ERROR"]
    assert "\033" in _Logger.COLORS["RESET"]
