import unittest

from eduid.common.utils import generate_password
from eduid.webapp.common.api.validation import is_valid_password


class TestIsValidPassword(unittest.TestCase):
    def test_is_valid_password(self) -> None:
        res = is_valid_password("abc123", [], min_entropy=1, min_score=0)
        self.assertEqual(True, res)

    def test_is_valid_password_empty(self) -> None:
        """Verify we get the right exception from empty passwords - zxcvbn crashes on them"""
        with self.assertRaises(ValueError):
            is_valid_password("", [], min_entropy=0, min_score=0)

    def test_is_valid_password_too_weak(self) -> None:
        with self.assertRaises(ValueError):
            is_valid_password("abc123", [], min_entropy=20, min_score=0)

    def test_is_valid_password_with_user_info(self) -> None:
        """Test that a password that is valid in itself becomes invalid if it is related to something in userinfo"""
        self.assertTrue(is_valid_password("BubbaHubba", [], min_entropy=20, min_score=0))
        with self.assertRaises(ValueError):
            is_valid_password("BubbaHubba", ["Hubba", "Bubba"], min_entropy=20, min_score=0)

    def test_is_valid_password_generated(self) -> None:
        """Test that a generated password is accepted with the parameters in use in production"""
        assert is_valid_password(generate_password(), [], min_entropy=25, min_score=3)

    def test_is_valid_password_generated_is_really_strong(self) -> None:
        """Test that a generated password is accepted with even higher parameters"""
        assert is_valid_password(generate_password(), [], min_entropy=35, min_score=4)
