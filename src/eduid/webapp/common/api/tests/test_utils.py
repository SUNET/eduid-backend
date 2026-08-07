from eduid.webapp.common.api.utils import make_short_code


def test_make_short_code_default_length() -> None:
    for _ in range(100):
        code = make_short_code()
        assert len(code) == 6
        assert code.isdigit()


def test_make_short_code_honours_digits() -> None:
    for digits in (4, 6, 8, 10):
        code = make_short_code(digits=digits)
        assert len(code) == digits
        assert code.isdigit()


def test_make_short_code_uses_full_keyspace() -> None:
    """digits=8 must produce values above 1e6, not a 6-digit value zero-padded to 8."""
    codes = [make_short_code(digits=8) for _ in range(2000)]
    assert any(int(code) >= 1_000_000 for code in codes), "keyspace still capped at 1e6"
    # The old implementation always produced "00" as the first two characters.
    assert any(not code.startswith("00") for code in codes)
