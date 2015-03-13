from unittest import TestCase

__author__ = 'ft'

import eduid_userdb.exceptions


class TestEduIDUserDBError(TestCase):

    def test_repr(self):
        ex = eduid_userdb.exceptions.EduIDUserDBError('test')
        self.assertIsInstance(str(ex), basestring)