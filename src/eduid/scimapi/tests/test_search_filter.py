import unittest

from eduid.common.misc.timeutil import utc_now
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.search import parse_search_filter


class TestSearchFilter(unittest.TestCase):
    def test_lastmodified(self) -> None:
        now = utc_now()
        filter = f'meta.lastModified gt "{now.isoformat()}"'
        sf = parse_search_filter(filter)
        self.assertEqual(sf.attr, "meta.lastmodified")
        self.assertEqual(sf.op, "gt")
        self.assertEqual(sf.val, now.isoformat())

    def test_lastmodified_with_tz(self) -> None:
        nowstr = "2020-05-05T09:13:43.916000+00:00"
        filter = f'meta.lastModified gt "{nowstr}"'
        sf = parse_search_filter(filter)
        self.assertEqual(sf.attr, "meta.lastmodified")
        self.assertEqual(sf.op, "gt")
        self.assertEqual(sf.val, nowstr)

    def test_str(self) -> None:
        filter = 'foo eq "123"'
        sf = parse_search_filter(filter)
        self.assertEqual(sf.attr, "foo")
        self.assertEqual(sf.op, "eq")
        self.assertEqual(sf.val, "123")

    def test_int(self) -> None:
        filter = "foo eq 123"
        sf = parse_search_filter(filter)
        self.assertEqual(sf.attr, "foo")
        self.assertEqual(sf.op, "eq")
        self.assertEqual(sf.val, 123)

    def test_not_printable(self) -> None:
        filter = "foo eq 12\u00093"
        with self.assertRaises(BadRequest):
            parse_search_filter(filter)
