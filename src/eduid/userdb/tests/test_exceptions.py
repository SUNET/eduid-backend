from unittest import TestCase

import eduid.userdb.exceptions

__author__ = "ft"


class TestEduIDUserDBError(TestCase):
    def test_repr(self) -> None:
        ex = eduid.userdb.exceptions.EduIDUserDBError("test")
        self.assertIsInstance(str(ex), str)
