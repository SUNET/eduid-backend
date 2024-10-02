import unittest
from datetime import datetime

from eduid.webapp.lookup_mobile_proofing.helpers import nin_to_age


class HelperTests(unittest.TestCase):
    def test_nin_to_age(self) -> None:
        now = datetime.fromisoformat("2021-08-21T00:00:00")
        assert nin_to_age("20210820abcd", now=now) == 0

        assert nin_to_age("202008211234", now=now) == 1

        assert nin_to_age("20200820abcd", now=now) == 1

        assert nin_to_age("20000101abcd", now=now) == 21
