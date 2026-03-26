from eduid.common.misc.timeutil import utc_now


class TimeUtilTests:
    def test_utc_now(self) -> None:
        t1 = utc_now()
        t2 = utc_now()
        assert t2 > t1

        assert str(t1).endswith("+00:00")
