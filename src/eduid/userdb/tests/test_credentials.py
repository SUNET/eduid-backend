import unittest
from hashlib import sha256

import pytest
from bson.objectid import ObjectId
from pydantic import ValidationError

import eduid.userdb.element
import eduid.userdb.exceptions
from eduid.userdb.credentials import U2F, CredentialList
from eduid.userdb.credentials.external import SwedenConnectCredential
from eduid.userdb.element import ElementKey

__author__ = 'lundberg'

# {'passwords': {
#    'id': password_id,
#    'salt': salt,
#    'source': 'signup',
#    'created_ts': datetime.datetime.utcnow(),
# }}
from eduid.userdb.credentials.password import Password

_one_dict = {
    'credential_id': '111111111111111111111111',
    'salt': 'firstPasswordElement',
    'is_generated': False,
}
_two_dict = {
    'credential_id': '222222222222222222222222',
    'salt': 'secondPasswordElement',
    'source': 'test',
}
_three_dict = {
    'credential_id': '333333333333333333333333',
    'salt': 'thirdPasswordElement',
    'source': 'test',
    'is_generated': True,
}
_four_dict = {
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'firstU2FElement',
    'public_key': 'foo',
}


def _keyid(key):
    return 'sha256:' + sha256(key['keyhandle'].encode('utf-8') + key['public_key'].encode('utf-8')).hexdigest()


class TestCredentialList(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None  # make pytest always show full diffs
        self.empty = CredentialList()
        self.one = CredentialList.from_list_of_dicts([_one_dict])
        self.two = CredentialList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = CredentialList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])
        self.four = CredentialList.from_list_of_dicts([_one_dict, _two_dict, _three_dict, _four_dict])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))
        self.assertEqual(4, len(self.four.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        expected = [_one_dict]
        obtained = self.one.to_list_of_dicts()

        assert obtained == expected, 'Credential list with one password not as expected'

    def test_find(self):
        match = self.two.find('222222222222222222222222')
        self.assertIsInstance(match, Password)
        self.assertEqual(match.credential_id, '222222222222222222222222')
        self.assertEqual(match.salt, 'secondPasswordElement')
        self.assertEqual(match.created_by, 'test')

    def test_filter(self):
        match = self.four.filter(U2F)
        assert len(match) == 1
        token = match[0]
        assert token.key == _keyid(_four_dict)
        assert token.public_key == 'foo'

    def test_add(self):
        second = self.two.find(str(ObjectId('222222222222222222222222')))
        self.one.add(second)

        expected = self.two.to_list_of_dicts()
        obtained = self.one.to_list_of_dicts()

        assert obtained == expected, 'List of credentials with added credential different than expected'

    def test_add_duplicate(self):
        dup = self.two.find(str(ObjectId('222222222222222222222222')))
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert exc_info.value.errors() == [
            {'loc': ('elements',), 'msg': 'Duplicate element key: \'222222222222222222222222\'', 'type': 'value_error'}
        ]

    def test_add_password(self):
        this = CredentialList.from_list_of_dicts([_one_dict, _two_dict] + [_three_dict])

        expected = self.three.to_list_of_dicts()
        obtained = this.to_list_of_dicts()

        assert obtained == expected, 'List of credentials with added password different than expected'

    def test_remove(self):
        self.three.remove(ElementKey(str(ObjectId('333333333333333333333333'))))
        now_two = self.three

        expected = self.two.to_list_of_dicts()
        obtained = now_two.to_list_of_dicts()

        assert obtained == expected, 'List of credentials with removed credential different than expected'

    def test_remove_unknown(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove(ElementKey(str(ObjectId('55002741d00690878ae9b603'))))

    def test_generated(self):
        match = self.three.find('222222222222222222222222')
        assert isinstance(match, Password)
        assert match.is_generated is False
        match = self.three.find('333333333333333333333333')
        assert isinstance(match, Password)
        assert match.is_generated is True

    def test_external_credential(self):
        _id = ElementKey(str(ObjectId()))
        # A SwedenConnectCredential as stored in the database
        data = {'framework': 'SWECONN', 'level': 'loa3', 'credential_id': _id}
        this = CredentialList.from_list_of_dicts([data])
        assert this.elements != []
        assert this.to_list_of_dicts() == [data]

        # check object access
        cred = this.elements[0]
        assert isinstance(cred, SwedenConnectCredential)
        assert cred.level == 'loa3'
        assert cred.key == _id
