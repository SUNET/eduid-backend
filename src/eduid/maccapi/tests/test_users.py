from eduid.userdb.maccapi import ManagedAccount
from eduid.maccapi.testing import MAccApiTestCase


class TestUser(MAccApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def test_create_user(self):
        user: ManagedAccount = self.add_user(eppn="ma-12345678", given_name="Test", surname="User")
        self.assertEqual(user.eppn, "ma-12345678")
        self.assertEqual(user.given_name, "Test")
        self.assertEqual(user.surname, "User")