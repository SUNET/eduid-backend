from unittest import TestCase
import eduid_userdb.exceptions

__author__ = 'ft'


class TestEduIDUserDBError(TestCase):

    def test_repr(self):
        ex = eduid_userdb.exceptions.EduIDUserDBError('test')
        self.assertIsInstance(str(ex), basestring)
