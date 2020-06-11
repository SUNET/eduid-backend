import unittest

from eduid_common.api.validation import is_valid_password


class TestIsValidPassword(unittest.TestCase):

    def test_is_valid_password(self):
        res = is_valid_password('abc123', [], 1)
        self.assertEqual(True, res)

    def test_is_valid_password_too_weak(self):
        with self.assertRaises(ValueError):
            is_valid_password('abc123', [], 20)

    def test_is_valid_password_with_user_info(self):
        """ Test that a password that is valid in itself becomes invalid if it is related to something in userinfo """
        self.assertTrue(is_valid_password('BubbaHubba', [], 20))
        with self.assertRaises(ValueError):
            is_valid_password('BubbaHubba', ['Hubba', 'Bubba'], 20)
