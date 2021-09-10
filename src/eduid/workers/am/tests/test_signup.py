from copy import deepcopy

import bson

from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.fixtures.users import mocked_user_standard
from eduid.userdb.signup import SignupUser
from eduid.userdb.testing import normalised_data
from eduid.workers.am.common import AmCelerySingleton
from eduid.workers.am.testing import USER_DATA, AMTestCase


class AttributeFetcherTests(AMTestCase):
    def setUp(self):
        am_settings = {'new_user_date': '2001-01-01'}
        super().setUp(am_settings=am_settings, am_users=[mocked_user_standard])

        self.fetcher = AmCelerySingleton.af_registry.get_fetcher('eduid_signup')

        for userdoc in self.amdb._get_all_docs():
            signup_user = SignupUser.from_dict(userdoc)
            self.fetcher.private_db.save(signup_user, check_sync=False)

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('000000000000000000000000'))

    def test_existing_user_from_db(self):
        fetched = self.fetcher.fetch_attrs(mocked_user_standard.user_id)

        expected_passwords = mocked_user_standard.credentials.to_list_of_dicts()
        expected_emails = mocked_user_standard.mail_addresses.to_list_of_dicts()

        expected = {
            '$set': {
                'eduPersonPrincipalName': 'hubba-bubba',
                'mailAliases': expected_emails,
                'passwords': expected_passwords,
            }
        }

        # normalise expected too since otherwise expected timestamps won't have timezone, but fetched timestamps will
        expected = normalised_data(expected)

        assert normalised_data(fetched) == expected

    def test_existing_user(self):
        user_data = deepcopy(USER_DATA)
        user_data['mail'] = 'johnsmith@example.com'
        user_data['mailAliases'] = [{'verified': True, 'email': 'johnsmith@example.com'}]
        del user_data['passwords']
        user = SignupUser.from_dict(user_data)
        self.fetcher.private_db.save(user)
        with self.assertRaises(ValueError):
            self.fetcher.fetch_attrs(bson.ObjectId(user.user_id))

    def test_user_without_aliases(self):
        user_data = deepcopy(USER_DATA)
        user_data['mail'] = 'johnsmith@example.com'
        del user_data['passwords']
        user = SignupUser.from_dict(user_data)
        self.fetcher.private_db.save(user)
        with self.assertRaises(ValueError):
            self.fetcher.fetch_attrs(bson.ObjectId(user.user_id))

    def test_user_finished_and_removed(self):
        user_data = deepcopy(USER_DATA)
        user_data['mail'] = 'john@example.com'
        user_data['mailAliases'] = [{'email': 'john@example.com', 'verified': True,}]
        user_data['passwords'] = [{'id': '123', 'salt': '456',}]
        user = SignupUser.from_dict(user_data)
        self.fetcher.private_db.save(user)

        fetched = self.fetcher.fetch_attrs(user.user_id)

        expected_passwords = [{'credential_id': u'123', 'is_generated': False, 'salt': u'456',}]

        expected_emails = [{'verified': True, 'primary': True, 'email': 'john@example.com'}]

        expected = {
            '$set': {
                'eduPersonPrincipalName': 'test-test',
                'mailAliases': expected_emails,
                'passwords': expected_passwords,
            }
        }

        assert normalised_data(fetched) == expected, 'Wrong data fetched by signup fetcher'

    def test_malicious_attributes(self):
        user_data = deepcopy(USER_DATA)
        user_data['foo'] = 'bar'
        user_data['mail'] = 'john@example.com'
        user_data['mailAliases'] = [{'email': 'john@example.com', 'verified': True,}]
        user_data['passwords'] = [{'id': '123', 'salt': '456',}]
        with self.assertRaises(TypeError):
            SignupUser.from_dict(user_data)
