from unittest import TestCase

from six import string_types

import eduid_userdb.exceptions

__author__ = 'ft'


class TestEduIDUserDBError(TestCase):
    def test_repr(self):
        ex = eduid_userdb.exceptions.EduIDUserDBError('test')
        self.assertIsInstance(str(ex), string_types)
