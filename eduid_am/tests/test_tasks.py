from __future__ import absolute_import

from bson import ObjectId

import eduid_userdb
from eduid_common.config.base import FlaskConfig
from eduid_common.config.workers import AmConfig
from eduid_userdb.exceptions import EduIDUserDBError, MultipleUsersReturned, UserDoesNotExist
from eduid_userdb.fixtures.users import mocked_user_standard
from eduid_userdb.locked_identity import LockedIdentityList, LockedIdentityNin

from eduid_am.consistency_checks import check_locked_identity, unverify_duplicates
from eduid_am.testing import AMTestCase


M = mocked_user_standard.to_dict()


class TestTasks(AMTestCase):
    def setUp(self):
        am_settings = {'want_mongo_uri': True}
        super(TestTasks, self).setUp(am_settings=am_settings)

    def fix_am_settings(self):
        self.am_settings = AmConfig(**self.am_settings)

    def fix_app_settings(self):
        self.settings = FlaskConfig(**self.settings)

    def test_get_user_by_id(self):
        user = self.amdb.get_user_by_id(M['_id'])
        self.assertEqual(user.mail_addresses.primary.email, M['mailAliases'][0]['email'])
        with self.assertRaises(UserDoesNotExist):
            self.amdb.get_user_by_id(b'123456789012')

    def test_get_user_by_mail(self):
        user = self.amdb.get_user_by_mail(M['mailAliases'][0]['email'])
        self.assertEqual(user.user_id, M['_id'])

        # Test unverified mail address in mailAliases, should raise UserDoesNotExist
        with self.assertRaises(UserDoesNotExist):
            self.amdb.get_user_by_mail(M['mailAliases'][2]['email'], raise_on_missing=True)

    def test_user_duplication_exception(self):
        user1 = self.amdb.get_user_by_mail(M['mailAliases'][0]['email'])
        user2_doc = user1.to_dict()
        user2_doc['_id'] = ObjectId()  # make up a new unique identifier
        del user2_doc['modified_ts']  # defeat sync-check mechanism
        self.amdb.save(eduid_userdb.User(data=user2_doc))
        with self.assertRaises(MultipleUsersReturned):
            self.amdb.get_user_by_mail(M['mailAliases'][0]['email'])

    def test_unverify_duplicate_mail(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        attributes = {
            '$set': {
                'mailAliases': [
                    {
                        'email': 'johnsmith@example.com',  # hubba-bubba's primary mail address
                        'verified': True,
                        'primary': True,
                        'created_ts': True,
                    }
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn('hubba-bubba')
        self.assertNotEqual(user.mail_addresses.primary.email, 'johnsmith@example.com')
        self.assertFalse(user.mail_addresses.find('johnsmith@example.com').is_verified)
        self.assertTrue(user.mail_addresses.primary)
        self.assertEqual(stats['mail_count'], 1)

    def test_unverify_duplicate_phone(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        attributes = {
            '$set': {
                'phone': [{'verified': True, 'number': '+34609609609', 'primary': True}]  # hubba-bubba's primary phone
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn('hubba-bubba')
        self.assertNotEqual(user.phone_numbers.primary.number, '+34609609609')
        self.assertFalse(user.phone_numbers.find('+34609609609').is_verified)
        self.assertTrue(user.phone_numbers.primary)
        self.assertEqual(stats['phone_count'], 1)

    def test_unverify_duplicate_nins(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        attributes = {
            '$set': {
                'nins': [{'verified': True, 'number': '197801011234', 'primary': True}]  # hubba-bubba's primary nin
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn('hubba-bubba')
        self.assertIsNone(user.nins.primary)
        self.assertFalse(user.nins.find('197801011234').is_verified)
        self.assertEqual(stats['nin_count'], 1)

    def test_unverify_duplicate_all(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        attributes = {
            '$set': {
                'mailAliases': [
                    {
                        'email': 'johnsmith@example.com',  # hubba-bubba's primary mail address
                        'verified': True,
                        'primary': True,
                        'created_ts': True,
                    }
                ],
                'phone': [{'verified': True, 'number': '+34609609609', 'primary': True}],  # hubba-bubba's primary phone
                'nins': [{'verified': True, 'number': '197801011234', 'primary': True}],  # hubba-bubba's primary nin
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn('hubba-bubba')

        self.assertNotEqual(user.mail_addresses.primary.email, 'johnsmith@example.com')
        self.assertFalse(user.mail_addresses.find('johnsmith@example.com').is_verified)
        self.assertTrue(user.mail_addresses.primary)

        self.assertNotEqual(user.phone_numbers.primary.number, '+34609609609')
        self.assertFalse(user.phone_numbers.find('+34609609609').is_verified)
        self.assertTrue(user.phone_numbers.primary)

        self.assertIsNone(user.nins.primary)
        self.assertFalse(user.nins.find('197801011234').is_verified)

        self.assertEqual(stats['mail_count'], 1)
        self.assertEqual(stats['phone_count'], 1)
        self.assertEqual(stats['nin_count'], 1)

    def test_unverify_duplicate_multiple_attribute_values(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        attributes = {
            '$set': {
                'mailAliases': [
                    {'email': 'johnsmith@example.net', 'verified': True, 'primary': True, 'created_ts': True},
                    {
                        'email': 'johnsmith@example.com',  # hubba-bubba's primary mail address
                        'verified': True,
                        'primary': True,
                        'created_ts': True,
                    },
                ]
            }
        }
        stats = unverify_duplicates(self.amdb, user_id, attributes)
        user = self.amdb.get_user_by_eppn('hubba-bubba')
        self.assertNotEqual(user.mail_addresses.primary.email, 'johnsmith@example.com')
        self.assertFalse(user.mail_addresses.find('johnsmith@example.com').is_verified)
        self.assertTrue(user.mail_addresses.primary)
        self.assertEqual(stats['mail_count'], 1)

    def test_create_locked_identity(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        attributes = {'$set': {'nins': [{'verified': True, 'number': '200102031234', 'primary': True}],}}
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, 'test')

        locked_nin = LockedIdentityNin('200102031234', 'test', True)
        locked_identities = LockedIdentityList({}).add(locked_nin)
        attributes['$set']['locked_identity'] = locked_identities.to_list_of_dicts()

        self.assertDictEqual(attributes, new_attributes)

    def test_check_locked_identity(self):
        user_id = ObjectId('012345678901234567890123')  # johnsmith@example.com / hubba-bubba
        user = self.amdb.get_user_by_id(user_id)
        user.locked_identity.add(LockedIdentityNin('197801011234', 'test', True))
        self.amdb.save(user)
        attributes = {
            '$set': {
                'nins': [{'verified': True, 'number': '197801011234', 'primary': True}],  # hubba-bubba's primary nin
            }
        }
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, 'test')

        locked_nin = LockedIdentityNin('197801011234', 'test', True)
        locked_identities = LockedIdentityList({}).add(locked_nin)
        attributes['$set']['locked_identity'] = locked_identities.to_list_of_dicts()

        self.assertDictEqual(attributes, new_attributes)

    def test_check_locked_identity_wrong_nin(self):
        user_id = ObjectId('901234567890123456789012')  # johnsmith@example.org / babba-labba
        user = self.amdb.get_user_by_id(user_id)
        user.locked_identity.add(LockedIdentityNin('200102031234', 'test', True))
        self.amdb.save(user)
        attributes = {'$set': {'nins': [{'verified': True, 'number': '200506076789', 'primary': True}],}}
        with self.assertRaises(EduIDUserDBError):
            check_locked_identity(self.amdb, user_id, attributes, 'test')

    def test_check_locked_identity_no_verified_nin(self):
        user_id = ObjectId('012345678901234567890123')  # johnsmith@example.com / hubba-bubba
        attributes = {'$set': {'phone': [{'verified': True, 'number': '+34609609609', 'primary': True}],}}
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, 'test')
        self.assertDictEqual(attributes, new_attributes)

        attributes = {'$set': {'nins': [{'verified': False, 'number': '200506076789', 'primary': False}],}}
        new_attributes = check_locked_identity(self.amdb, user_id, attributes, 'test')
        self.assertDictEqual(attributes, new_attributes)
