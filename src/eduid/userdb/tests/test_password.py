import datetime
from unittest import TestCase

from bson.objectid import ObjectId

from eduid.userdb.credentials import CredentialList, Password

__author__ = "lundberg"


_one_dict = {
    "id": "55002741d00690878ae9b600",
    "salt": "firstPasswordElement",
}
_two_dict = {"id": "55002741d00690878ae9b601", "salt": "secondPasswordElement", "source": "test"}
_three_dict = {"id": "55002741d00690878ae9b602", "salt": "thirdPasswordElement", "source": "test"}


class TestPassword(TestCase):
    def setUp(self) -> None:
        self.empty = CredentialList()
        self.one = CredentialList.from_list_of_dicts([_one_dict])
        self.two = CredentialList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = CredentialList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self) -> None:
        """
        Test that the 'key' property (used by CredentialList) works for the Password.
        """
        password = self.one.find(str(ObjectId("55002741d00690878ae9b600")))
        assert password
        assert isinstance(password, Password)
        self.assertEqual(password.key, password.credential_id)

    def test_parse_cycle(self) -> None:
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(CredentialList.from_list_of_dicts(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_created_by(self) -> None:
        this = self.three.find(str(ObjectId("55002741d00690878ae9b600")))
        assert this
        this.created_by = "unit test"
        self.assertEqual(this.created_by, "unit test")

    def test_created_ts(self) -> None:
        this = self.three.find(str(ObjectId("55002741d00690878ae9b600")))
        assert this
        self.assertIsInstance(this.created_ts, datetime.datetime)
