import unittest

from eduid.common.misc.timeutil import utc_now
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.search import parse_search_filter


class TestSearchFilter(unittest.TestCase):
    def test_lastmodified(self) -> None:
        now = utc_now()
        search_filter = f'meta.lastModified gt "{now.isoformat()}"'
        sf = parse_search_filter(search_filter)
        assert sf.attr == "meta.lastmodified"
        assert sf.op == "gt"
        assert sf.val == now.isoformat()

    def test_lastmodified_with_tz(self) -> None:
        nowstr = "2020-05-05T09:13:43.916000+00:00"
        search_filter = f'meta.lastModified gt "{nowstr}"'
        sf = parse_search_filter(search_filter)
        assert sf.attr == "meta.lastmodified"
        assert sf.op == "gt"
        assert sf.val == nowstr

    def test_str(self) -> None:
        search_filter = 'foo eq "123"'
        sf = parse_search_filter(search_filter)
        assert sf.attr == "foo"
        assert sf.op == "eq"
        assert sf.val == "123"

    def test_int(self) -> None:
        search_filter = "foo eq 123"
        sf = parse_search_filter(search_filter)
        assert sf.attr == "foo"
        assert sf.op == "eq"
        assert sf.val == 123

    def test_not_printable(self) -> None:
        search_filter = "foo eq 12\u00093"
        with self.assertRaises(BadRequest):
            parse_search_filter(search_filter)
