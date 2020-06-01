import datetime
from hashlib import sha256
from unittest import TestCase

from bson import ObjectId
from six import string_types

from eduid_userdb import LockedIdentityNin, OidcAuthorization, OidcIdToken, Orcid
from eduid_userdb.credentials import METHOD_SWAMID_AL2_MFA, CredentialList
from eduid_userdb.exceptions import EduIDUserDBError, UserHasNotCompletedSignup, UserHasUnknownData, UserIsRevoked
from eduid_userdb.mail import MailAddressList
from eduid_userdb.nin import NinList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.profile import Profile, ProfileList
from eduid_userdb.tou import ToUList
from eduid_userdb.user import User

__author__ = 'ft'


def _keyid(kh):
    return 'sha256:' + sha256(kh.encode('utf-8')).hexdigest()


class _AbstractUserTestCase:
    def test_user_id(self):
        self.assertEqual(self.user1.user_id, self.data1['_id'])

    def test_eppn(self):
        self.assertEqual(self.user1.eppn, self.data1['eduPersonPrincipalName'])

    def test_given_name(self):
        self.assertEqual(self.user2.given_name, self.data2['givenName'])

    def test_display_name(self):
        self.assertEqual(self.user2.display_name, self.data2['displayName'])

    def test_surname(self):
        self.assertEqual(self.user2.surname, self.data2['surname'])

    def test_mail_addresses(self):
        self.assertEqual(self.user1.mail_addresses.primary.email, self.data1['mailAliases'][0]['email'])

    def test_passwords(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        self.assertEqual(self.user1.passwords.to_list_of_dicts(old_userdb_format=True), self.data1['passwords'])

    def test_obsolete_attributes(self):
        """
        Test that some obsolete attributes don't cause parse failures.
        """
        data = self.data1
        data['postalAddress'] = {'foo': 'bar'}
        data['date'] = 'anything'
        data['csrf'] = 'long and secret string'
        data['mailAliases'][0]['verification_code'] = '123456789'
        user = User(data)
        self.assertEqual(self.user1._data, user._data)

        data = self.data2
        data['mobile'][0]['verification_code'] = '123456789'
        user = User(data)
        self.assertEqual(self.user2._data, user._data)

    def test_unknown_attributes(self):
        """
        Test parsing a document with unknown data in it.
        """
        data = self.data1
        data['unknown_attribute'] = 'something'
        user = User(data, raise_on_unknown=False)
        self.assertEqual(data['_id'], user.user_id)

        with self.assertRaises(UserHasUnknownData):
            User(data, raise_on_unknown=True)

    def test_incomplete_signup_user(self):
        """
        Test parsing the incomplete documents left in the central userdb by older Signup application.
        """
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'vohon-mufus',
            u'mail': u'olle@example.org',
            u'mailAliases': [{u'email': u'olle@example.org', u'verified': False}],
        }
        with self.assertRaises(UserHasNotCompletedSignup):
            User(data)
        data['subject'] = 'physical person'  # later signup added this attribute
        with self.assertRaises(UserHasNotCompletedSignup):
            User(data)
        data[u'mailAliases'][0]['verified'] = True
        data['surname'] = 'not signup-incomplete anymore'
        data['passwords'] = [
            {
                u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                u'credential_id': str(ObjectId()),
                u'salt': u'salt',
                u'created_by': u'dashboard',
                u'is_generated': False,
            }
        ]
        user = User(data)
        self.assertEqual(user.surname, data['surname'])
        self.assertEqual(user.passwords.to_list_of_dicts(), data['passwords'])

    def test_revoked_user(self):
        """
        Test ability to identify revoked users.
        """
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'binib-mufus',
            u'revoked_ts': datetime.datetime(2015, 5, 26, 8, 33, 56, 826000),
        }
        with self.assertRaises(UserIsRevoked):
            User(data)

    def test_user_with_no_primary_mail(self):
        mail = u'yahoo@example.com'
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'lutol-bafim',
            u'mailAliases': [{u'email': mail, u'verified': True}],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User(data)
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_user_with_indirectly_verified_primary_mail(self):
        """
        If a user has passwords set, the 'mail' attribute will be considered indirectly verified.
        """
        mail = u'yahoo@example.com'
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'lutol-bafim',
            u'mail': mail,
            u'mailAliases': [{u'email': mail, u'verified': False}],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User(data)
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_user_with_indirectly_verified_primary_mail_and_explicit_primary_mail(self):
        """
        If a user has manage to verify a mail address in the new style with the same address still
        set in old style mail property. Do not make old mail address primary if a primary all ready exists.
        """
        old_mail = u'yahoo@example.com'
        new_mail = u'not_yahoo@example.com'
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'lutol-bafim',
            u'mail': old_mail,
            u'mailAliases': [
                {u'email': old_mail, u'verified': True, u'primary': False},
                {u'email': new_mail, u'verified': True, u'primary': True},
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User(data)
        self.assertEqual(new_mail, user.mail_addresses.primary.email)

    def test_user_with_csrf_junk_in_mail_address(self):
        """
        For a long time, Dashboard leaked CSRF tokens into the mail address dicts.
        """
        mail = u'yahoo@example.com'
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'test-test',
            u'mailAliases': [{u'email': mail, u'verified': True, u'csrf': u'6ae1d4e95305b72318a683883e70e3b8e302cd75'}],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User(data)
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_to_dict(self):
        """
        Test that User objects can be recreated.
        """
        d1 = self.user1.to_dict()
        u2 = User(d1)
        d2 = u2.to_dict()
        self.assertEqual(d1, d2)

    def test_to_dict_old_format(self):
        """
        Test that User objects can be recreated.
        """
        d1 = self.user1.to_dict(old_userdb_format=True)
        u2 = User(d1)
        d2 = u2.to_dict(old_userdb_format=True)
        self.assertEqual(d1, d2)

    def test_modified_ts(self):
        """
        Test the modified_ts property.
        """
        # ensure known starting point
        self.assertIsNone(self.user1.modified_ts)
        # set to current time
        self.user1.modified_ts = True
        _time1 = self.user1.modified_ts
        self.assertIsInstance(_time1, datetime.datetime)
        # Setting existing value to None should be ignored
        self.user1.modified_ts = None
        self.assertEqual(_time1, self.user1.modified_ts)
        # update to current time
        self.user1.modified_ts = True
        _time2 = self.user1.modified_ts
        self.assertNotEqual(_time1, _time2)
        # set to a datetime instance
        self.user1.modified_ts = _time1
        self.assertEqual(_time1, self.user1.modified_ts)

    def test_two_unverified_non_primary_phones(self):
        """
        Test that the first entry in the `phone' list is chosen as primary when none are verified.
        """
        number1 = u'+9112345678'
        number2 = u'+9123456789'
        data = {
            u'_id': ObjectId(),
            u'displayName': u'xxx yyy',
            u'eduPersonPrincipalName': u'pohig-test',
            u'givenName': u'xxx',
            u'mail': u'test@gmail.com',
            u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
            u'phone': [
                {
                    u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                    u'number': number1,
                    u'primary': False,
                    u'verified': False,
                },
                {
                    u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                    u'number': number2,
                    u'primary': False,
                    u'verified': False,
                },
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 6, 29, 17, 52, 37, 830000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
            u'preferredLanguage': u'en',
            u'surname': u'yyy',
        }
        user = User(data)
        self.assertEqual(user.phone_numbers.primary, None)

    def test_two_non_primary_phones(self):
        """
        Test that the first verified number is chosen as primary, if there is a verified number.
        """
        number1 = u'+9112345678'
        number2 = u'+9123456789'
        data = {
            u'_id': ObjectId(),
            u'displayName': u'xxx yyy',
            u'eduPersonPrincipalName': u'pohig-test',
            u'givenName': u'xxx',
            u'mail': u'test@gmail.com',
            u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
            u'phone': [
                {
                    u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                    u'number': number1,
                    u'primary': False,
                    u'verified': False,
                },
                {
                    u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                    u'number': number2,
                    u'primary': False,
                    u'verified': True,
                },
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 6, 29, 17, 52, 37, 830000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
            u'preferredLanguage': u'en',
            u'surname': u'yyy',
        }
        user = User(data)
        self.assertEqual(user.phone_numbers.primary.number, number2)

    def test_primary_non_verified_phone(self):
        """
        Test that if a non verified phone number is primary, due to earlier error, then that primary flag is removed.
        """
        data = {
            u'_id': ObjectId(),
            u'displayName': u'xxx yyy',
            u'eduPersonPrincipalName': u'pohig-test',
            u'givenName': u'xxx',
            u'mail': u'test@gmail.com',
            u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
            u'phone': [
                {
                    u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                    u'number': u'+9112345678',
                    u'primary': True,
                    u'verified': False,
                }
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 6, 29, 17, 52, 37, 830000),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
            u'preferredLanguage': u'en',
            u'surname': u'yyy',
        }
        user = User(data)
        for number in user.phone_numbers.to_list():
            self.assertEqual(number.is_primary, False)

    def test_primary_non_verified_phone2(self):
        """
        Test that if a non verified phone number is primary, due to earlier error, then that primary flag is removed.
        """
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'pohig-test',
            u'mail': u'test@gmail.com',
            u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
            u'phone': [
                {u'number': u'+11111111111', u'primary': True, u'verified': False},
                {u'number': u'+22222222222', u'primary': False, u'verified': True,},
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 6, 29, 17, 52, 37, 830000),
                    u'id': ObjectId(),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User(data)
        self.assertEqual(user.phone_numbers.primary.number, u'+22222222222')

    def test_user_tou(self):
        """
        Basic test for user ToU.
        """
        tou_dict = {
            'event_id': ObjectId(),
            'event_type': 'tou_event',
            'version': '1',
            'created_by': 'unit test',
            'created_ts': True,
        }
        tou_events = ToUList([tou_dict])
        data = self.data1
        data.update({'tou': tou_events.to_list_of_dicts()})
        user = User(data)
        self.assertTrue(user.tou.has_accepted('1', reaccept_interval=94608000))  # reaccept_interval seconds (3 years)
        self.assertFalse(user.tou.has_accepted('2', reaccept_interval=94608000))  # reaccept_interval seconds (3 years)

    def test_locked_identity_load(self):
        locked_identity = {'created_by': 'test', 'created_ts': True, 'identity_type': 'nin', 'number': '197801012345'}
        data = self.data1
        data['locked_identity'] = [locked_identity]
        user = User(data)
        self.assertTrue(user.locked_identity)
        self.assertIsInstance(user.locked_identity.find('nin').created_by, string_types)
        self.assertIsInstance(user.locked_identity.find('nin').created_ts, datetime.datetime)
        self.assertIsInstance(user.locked_identity.find('nin').identity_type, string_types)
        self.assertIsInstance(user.locked_identity.find('nin').number, string_types)

    def test_locked_identity_set(self):
        locked_identity = {'created_by': 'test', 'created_ts': True, 'identity_type': 'nin', 'number': '197801012345'}
        user = User(self.data1)
        locked_nin = LockedIdentityNin(
            locked_identity['number'], locked_identity['created_by'], locked_identity['created_ts']
        )
        user.locked_identity.add(locked_nin)
        self.assertEqual(user.locked_identity.count, 1)

        locked_nin = user.locked_identity.find('nin')
        self.assertIsInstance(locked_nin.created_by, string_types)
        self.assertIsInstance(locked_nin.created_ts, datetime.datetime)
        self.assertIsInstance(locked_nin.identity_type, string_types)
        self.assertIsInstance(locked_nin.number, string_types)

    def test_locked_identity_to_dict(self):
        locked_identity = {'created_by': 'test', 'created_ts': True, 'identity_type': 'nin', 'number': '197801012345'}
        user = User(self.data1)
        locked_nin = LockedIdentityNin(
            locked_identity['number'], locked_identity['created_by'], locked_identity['created_ts']
        )
        user.locked_identity.add(locked_nin)

        old_user = User(user.to_dict(old_userdb_format=True))
        self.assertEqual(user.locked_identity.count, 1)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].created_by, string_types)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].created_ts, datetime.datetime)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].identity_type, string_types)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].number, string_types)

        new_user = User(user.to_dict(old_userdb_format=False))
        self.assertEqual(user.locked_identity.count, 1)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].created_by, string_types)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].created_ts, datetime.datetime)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].identity_type, string_types)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].number, string_types)

    def test_locked_identity_remove(self):
        locked_identity = {'created_by': 'test', 'created_ts': True, 'identity_type': 'nin', 'number': '197801012345'}
        user = User(self.data1)
        locked_nin = LockedIdentityNin(
            locked_identity['number'], locked_identity['created_by'], locked_identity['created_ts']
        )
        user.locked_identity.add(locked_nin)
        with self.assertRaises(EduIDUserDBError):
            user.locked_identity.remove('nin')

    def test_orcid(self):
        id_token = {
            "aud": ["APP_ID"],
            "auth_time": 1526389879,
            "exp": 1526392540,
            "iat": 1526391940,
            "iss": "https://op.example.org",
            "sub": "subject_identifier",
            "nonce": "a_nonce_token",
        }
        oidc_data = {
            "access_token": "b8b8ca5d-b233-4d49-830a-ede934c626d3",
            "expires_in": 631138518,
            "refresh_token": "a110e7d2-4968-42d4-a91d-f379b55a0e60",
            "token_type": "bearer",
        }
        orcid = "user_orcid"
        oidc_id_token = OidcIdToken(application='test', **id_token)
        oidc_authz = OidcAuthorization(id_token=oidc_id_token, application='test', **oidc_data)
        orcid_element = Orcid(id=orcid, oidc_authz=oidc_authz, application='test')

        user = User(self.data1)
        user.orcid = orcid_element

        old_user = User(user.to_dict(old_userdb_format=True))
        self.assertIsNotNone(old_user.orcid)
        self.assertIsInstance(old_user.orcid.created_by, string_types)
        self.assertIsInstance(old_user.orcid.created_ts, datetime.datetime)
        self.assertIsInstance(old_user.orcid.id, string_types)
        self.assertIsInstance(old_user.orcid.oidc_authz, OidcAuthorization)
        self.assertIsInstance(old_user.orcid.oidc_authz.id_token, OidcIdToken)

        new_user = User(user.to_dict(old_userdb_format=False))
        self.assertIsNotNone(new_user.orcid)
        self.assertIsInstance(new_user.orcid.created_by, string_types)
        self.assertIsInstance(new_user.orcid.created_ts, datetime.datetime)
        self.assertIsInstance(new_user.orcid.id, string_types)
        self.assertIsInstance(new_user.orcid.oidc_authz, OidcAuthorization)
        self.assertIsInstance(new_user.orcid.oidc_authz.id_token, OidcIdToken)

    def test_profiles(self):
        self.assertIsNotNone(self.user1.profiles)
        self.assertEqual(self.user1.profiles.count, 0)
        self.assertIsNotNone(self.user2.profiles)
        self.assertEqual(self.user2.profiles.count, 1)

    def test_user_verified_credentials(self):
        ver = [x for x in self.user2.credentials.to_list() if x.is_verified]
        keys = [x.key for x in ver]
        self.assertEqual(keys, [_keyid('U2F SWAMID AL2' + 'foo')])

    def test_user_unverified_credential(self):
        cred = [x for x in self.user2.credentials.to_list() if x.is_verified][0]
        self.assertEqual(cred.proofing_method, METHOD_SWAMID_AL2_MFA)
        _dict1 = cred.to_dict()
        self.assertEqual(_dict1['verified'], True)
        self.assertEqual(_dict1['proofing_method'], METHOD_SWAMID_AL2_MFA)
        self.assertEqual(_dict1['proofing_version'], 'testing')
        cred.is_verified = False
        _dict2 = cred.to_dict()
        self.assertFalse('verified' in _dict2)
        self.assertFalse('proofing_method' in _dict2)
        self.assertFalse('proofing_version' in _dict2)

    def test_both_mobile_and_phone(self):
        """ Test user that has both 'mobile' and 'phone' """
        phone = [
            {'number': '+4673123', 'primary': True, 'verified': True},
            {
                'created_by': 'phone',
                'created_ts': datetime.datetime.utcnow(),
                'number': '+4670999',
                'primary': False,
                'verified': False,
            },
        ]
        user = User(
            data={
                '_id': ObjectId(),
                'eduPersonPrincipalName': 'test-test',
                'passwords': [],
                'mobile': [{'mobile': '+4673123', 'primary': True, 'verified': True}],
                'phone': phone,
            }
        )
        out = user.to_dict()['phone']
        self.assertEqual(phone, out)

    def test_both_sn_and_surname(self):
        """ Test user that has both 'sn' and 'surname' """
        user = User(
            data={
                '_id': ObjectId(),
                'eduPersonPrincipalName': 'test-test',
                'passwords': [],
                'surname': 'Right',
                'sn': 'Wrong',
            }
        )
        self.assertEqual('Right', user.to_dict()['surname'])

    def test_rebuild_user1(self):
        data = self.user1.to_dict()
        new_user1 = User.from_dict(data)
        self.assertEqual(new_user1.eppn, 'guvat-nalif')

    def test_rebuild_user2(self):
        data = self.user2.to_dict()
        new_user2 = User.from_dict(data)
        self.assertEqual(new_user2.eppn, 'birub-gagoz')


class TestUser(TestCase, _AbstractUserTestCase):
    def setUp(self):
        self.data1 = {
            u'_id': ObjectId('547357c3d00690878ae9b620'),
            u'eduPersonPrincipalName': u'guvat-nalif',
            u'mail': u'user@example.net',
            u'mailAliases': [
                {
                    u'added_timestamp': datetime.datetime(2014, 12, 18, 11, 25, 19, 804000),
                    u'email': u'user@example.net',
                    u'verified': True,
                }
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2014, 11, 24, 16, 22, 49, 188000),
                    u'credential_id': '54735b588a7d2a2c4ec3e7d0',
                    u'salt': u'$NDNv1H1$315d7$32$32$',
                    u'created_by': u'dashboard',
                    u'is_generated': False,
                }
            ],
            u'norEduPersonNIN': [u'197801012345'],
            u'subject': u'physical person',
            u'eduPersonEntitlement': [u'http://foo.example.org'],
            u'preferredLanguage': u'en',
        }
        self.user1 = User(self.data1)

        self.data2 = {
            u'_id': ObjectId('549190b5d00690878ae9b622'),
            u'displayName': u'Some \xf6ne',
            u'eduPersonPrincipalName': u'birub-gagoz',
            u'givenName': u'Some',
            u'mail': u'some.one@gmail.com',
            u'mailAliases': [
                {u'email': u'someone+test1@gmail.com', u'verified': True},
                {
                    u'added_timestamp': datetime.datetime(2014, 12, 17, 14, 35, 14, 728000),
                    u'email': u'some.one@gmail.com',
                    u'verified': True,
                },
            ],
            u'mobile': [
                {
                    u'added_timestamp': datetime.datetime(2014, 12, 18, 9, 11, 35, 78000),
                    u'mobile': u'+46702222222',
                    u'primary': True,
                    u'verified': True,
                }
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.datetime(2015, 2, 11, 13, 58, 42, 327000),
                    u'id': ObjectId('54db60128a7d2a26e8690cda'),
                    u'salt': u'$NDNv1H1$db011fc$32$32$',
                    u'is_generated': False,
                    u'source': u'dashboard',
                },
                {
                    'version': 'U2F_V2',
                    'app_id': 'unit test',
                    'keyhandle': 'U2F SWAMID AL2',
                    'public_key': 'foo',
                    'verified': True,
                    'proofing_method': METHOD_SWAMID_AL2_MFA,
                    'proofing_version': 'testing',
                },
            ],
            u'profiles': [
                {
                    'created_by': 'test application',
                    'created_ts': datetime.datetime(2020, 2, 4, 17, 42, 33, 696751),
                    'owner': 'test owner 1',
                    'schema': 'test schema',
                    'profile_data': {
                        'a_string': 'I am a string',
                        'an_int': 3,
                        'a_list': ['eins', 2, 'drei'],
                        'a_map': {'some': 'data'},
                    },
                }
            ],
            u'preferredLanguage': u'sv',
            u'surname': u'\xf6ne',
            u'subject': u'physical person',
        }
        self.user2 = User(self.data2)

    def test_mail_addresses_to_old_userdb_format(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        to_dict_result = self.user1.mail_addresses.to_list_of_dicts(old_userdb_format=True)
        self.assertEqual(to_dict_result, self.data1['mailAliases'])

    def test_phone_numbers(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        to_dict_result = self.user2.phone_numbers.to_list_of_dicts(old_userdb_format=True)
        self.assertEqual(to_dict_result, self.data2['mobile'])


class TestNewUser(TestCase, _AbstractUserTestCase):
    def setUp(self):
        self._setup_user1()
        self._setup_user2()

    def _setup_user1(self):
        _id = ObjectId('547357c3d00690878ae9b620')
        eppn = 'guvat-nalif'
        mail = 'user@example.net'
        mailAliases_list = [
            {
                'created_ts': datetime.datetime(2014, 12, 18, 11, 25, 19, 804000),
                'email': 'user@example.net',
                'verified': True,
                'primary': True,
            }
        ]
        mail_addresses = MailAddressList(mailAliases_list)
        password_list = [
            {
                'created_ts': datetime.datetime(2014, 11, 24, 16, 22, 49, 188000),
                'credential_id': '54735b588a7d2a2c4ec3e7d0',
                'salt': '$NDNv1H1$315d7$32$32$',
                'created_by': 'dashboard',
                'is_generated': False,
            }
        ]
        passwords = CredentialList(password_list)
        nin_list = [
            {
                'number': '197801012345',
                'created_ts': datetime.datetime(2014, 11, 24, 16, 22, 49, 188000),
                'verified': True,
                'primary': True,
                'created_by': 'dashboard',
            }
        ]
        nins = NinList(nin_list)
        subject = 'physical person'
        entitlements = [u'http://foo.example.org']
        language = 'en'

        self.user1 = User.construct_user(
            _id=_id,
            eppn=eppn,
            mail_addresses=mail_addresses,
            passwords=passwords,
            nins=nins,
            subject=subject,
            entitlements=entitlements,
            language=language,
        )

        self.data1 = {
            '_id': _id,
            'eduPersonPrincipalName': eppn,
            'mail': mail,
            'mailAliases': mail_addresses.to_list_of_dicts(),
            'passwords': passwords.to_list_of_dicts(),
            'nins': nins.to_list_of_dicts(),
            'subject': subject,
            'eduPersonEntitlement': entitlements,
            'preferredLanguage': language,
        }

    def _setup_user2(self):
        _id = ObjectId('549190b5d00690878ae9b622')
        display_name = 'Some \xf6ne'
        eppn = 'birub-gagoz'
        given_name = 'Some'
        mail = 'some.one@gmail.com'
        mailAliases_list = [
            {'email': 'someone+test1@gmail.com', 'verified': True},
            {
                'created_ts': datetime.datetime(2014, 12, 17, 14, 35, 14, 728000),
                'email': 'some.one@gmail.com',
                'verified': True,
                'primary': True,
            },
        ]
        mail_addresses = MailAddressList(mailAliases_list)
        phone_list = [
            {
                'created_ts': datetime.datetime(2014, 12, 18, 9, 11, 35, 78000),
                'number': '+46702222222',
                'primary': True,
                'verified': True,
            }
        ]
        phone_numbers = PhoneNumberList(phone_list)
        password_list = [
            {
                'created_ts': datetime.datetime(2015, 2, 11, 13, 58, 42, 327000),
                'id': ObjectId('54db60128a7d2a26e8690cda'),
                'salt': '$NDNv1H1$db011fc$32$32$',
                'is_generated': False,
                'source': 'dashboard',
            },
            {
                'version': 'U2F_V2',
                'app_id': 'unit test',
                'keyhandle': 'U2F SWAMID AL2',
                'public_key': 'foo',
                'verified': True,
                'proofing_method': METHOD_SWAMID_AL2_MFA,
                'proofing_version': 'testing',
            },
        ]
        passwords = CredentialList(password_list)
        profile_dict = {
            'created_by': 'test application',
            'created_ts': datetime.datetime(2020, 2, 4, 17, 42, 33, 696751),
            'owner': 'test owner 1',
            'schema': 'test schema',
            'profile_data': {
                'a_string': 'I am a string',
                'an_int': 3,
                'a_list': ['eins', 2, 'drei'],
                'a_map': {'some': 'data'},
            },
        }
        profile = Profile(**profile_dict)
        profile_list = [profile]
        profiles = ProfileList(profile_list)
        language = 'sv'
        surname = '\xf6ne'
        subject = 'physical person'

        self.user2 = User.construct_user(
            _id=_id,
            eppn=eppn,
            display_name=display_name,
            given_name=given_name,
            mail_addresses=mail_addresses,
            phone_numbers=phone_numbers,
            passwords=passwords,
            profiles=profiles,
            language=language,
            surname=surname,
            subject=subject,
        )

        self.data2 = {
            '_id': _id,
            'displayName': display_name,
            'eduPersonPrincipalName': eppn,
            'givenName': given_name,
            'mail': mail,
            'mailAliases': mail_addresses.to_list_of_dicts(),
            'mobile': phone_numbers.to_list_of_dicts(),
            'passwords': passwords.to_list_of_dicts(),
            'profiles': profiles.to_list_of_dicts(),
            'preferredLanguage': language,
            'surname': surname,
            'subject': subject,
        }

    def test_mail_addresses_to_new_userdb_format(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        to_dict_result = self.user1.mail_addresses.to_list_of_dicts()
        self.assertEqual(to_dict_result, self.data1['mailAliases'])

    def test_phone_numbers(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        to_dict_result = self.user2.phone_numbers.to_list_of_dicts()
        self.assertEqual(to_dict_result, self.data2['mobile'])

    def test_passwords_new_format(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        self.assertEqual(self.user1.passwords.to_list_of_dicts(), self.data1['passwords'])
