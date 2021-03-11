from unittest import TestCase

from six import string_types

import eduid.userdb.exceptions

__author__ = 'ft'


class TestEduIDUserDBError(TestCase):
    def test_repr(self):
        ex = eduid.userdb.exceptions.EduIDUserDBError('test')
        self.assertIsInstance(str(ex), string_types)
