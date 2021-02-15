import unittest
from datetime import datetime
from hashlib import sha256

from bson import ObjectId
from six import string_types

from eduid_userdb import LockedIdentityNin, OidcAuthorization, OidcIdToken, Orcid
from eduid_userdb.credentials import METHOD_SWAMID_AL2_MFA, U2F, CredentialList, Password
from eduid_userdb.exceptions import EduIDUserDBError, UserHasNotCompletedSignup, UserIsRevoked
from eduid_userdb.mail import MailAddress, MailAddressList
from eduid_userdb.nin import Nin, NinList
from eduid_userdb.phone import PhoneNumber, PhoneNumberList
from eduid_userdb.profile import Profile, ProfileList
from eduid_userdb.tou import ToUList
from eduid_userdb.user import SubjectType, User

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
        expected = self.data1['passwords']
        obtained = self.user1.credentials.to_list_of_dicts()

        assert obtained == expected

    def test_obsolete_attributes(self):
        """
        Test that some obsolete attributes don't cause parse failures.
        """
        data = self.data1
        data['postalAddress'] = {'foo': 'bar'}
        data['date'] = 'anything'
        data['csrf'] = 'long and secret string'
        data['mailAliases'][0]['verification_code'] = '123456789'
        user = User.from_dict(data)

        expected = self.user1.to_dict()
        obtained = user.to_dict()

        assert obtained == expected

        data = self.data2
        data['phone'][0]['verification_code'] = '123456789'
        user = User.from_dict(data)

        expected = self.user2.to_dict()
        obtained = user.to_dict()

        assert obtained == expected

    def test_unknown_attributes(self):
        """
        Test parsing a document with unknown data in it.
        """
        data = self.data1
        data['unknown_attribute'] = 'something'

        with self.assertRaises(TypeError):
            User.from_dict(data)

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
            User.from_dict(data)
        data['subject'] = 'physical person'  # later signup added this attribute
        with self.assertRaises(UserHasNotCompletedSignup):
            User.from_dict(data)
        data[u'mailAliases'][0]['verified'] = True
        data['surname'] = 'not signup-incomplete anymore'
        data['passwords'] = [
            {
                u'created_ts': datetime.fromisoformat('2014-09-04T08:57:07.362000'),
                u'credential_id': str(ObjectId()),
                u'salt': u'salt',
                u'created_by': u'dashboard',
                u'is_generated': False,
            }
        ]
        user = User.from_dict(data)
        self.assertEqual(user.surname, data['surname'])

        expected = data['passwords']
        obtained = user.credentials.to_list_of_dicts()

        assert obtained == expected

    def test_revoked_user(self):
        """
        Test ability to identify revoked users.
        """
        data = {
            '_id': ObjectId(),
            'eduPersonPrincipalName': 'binib-mufus',
            'revoked_ts': datetime.fromisoformat('2015-05-26T08:33:56.826000'),
            'passwords': [],
        }
        with self.assertRaises(UserIsRevoked):
            User.from_dict(data)

    def test_user_with_no_primary_mail(self):
        mail = u'yahoo@example.com'
        data = {
            u'_id': ObjectId(),
            u'eduPersonPrincipalName': u'lutol-bafim',
            u'mailAliases': [{u'email': mail, u'verified': True}],
            u'passwords': [
                {
                    u'created_ts': datetime.fromisoformat('2014-09-04T08:57:07.362000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User.from_dict(data)
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
                    u'created_ts': datetime.fromisoformat('2014-09-04T08:57:07.362000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User.from_dict(data)
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
                    u'created_ts': datetime.fromisoformat('2014-09-04T08:57:07.362000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User.from_dict(data)
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
                    u'created_ts': datetime.fromisoformat('2014-09-04T08:57:07.362000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'salt',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User.from_dict(data)
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_to_dict(self):
        """
        Test that User objects can be recreated.
        """
        d1 = self.user1.to_dict()
        u2 = User.from_dict(d1)
        d2 = u2.to_dict()
        self.assertEqual(d1, d2)

    def test_modified_ts(self):
        """
        Test the modified_ts property.
        """
        _time1 = self.user1.modified_ts
        assert _time1 is None
        # update to current time
        self.user1.modified_ts = datetime.utcnow()
        _time2 = self.user1.modified_ts
        self.assertNotEqual(_time1, _time2)
        # set to a datetime instance
        self.user1.modified_ts = datetime.utcnow()
        self.assertNotEqual(_time2, self.user1.modified_ts)

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
                    u'created_ts': datetime.fromisoformat('2014-06-29T17:52:37.830000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
            u'preferredLanguage': u'en',
            u'surname': u'yyy',
        }
        user = User.from_dict(data)
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
                    u'created_ts': datetime.fromisoformat('2014-06-29T17:52:37.830000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
            u'preferredLanguage': u'en',
            u'surname': u'yyy',
        }
        user = User.from_dict(data)
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
                    u'created_ts': datetime.fromisoformat('2014-06-29T17:52:37.830000'),
                    u'credential_id': str(ObjectId()),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
            u'preferredLanguage': u'en',
            u'surname': u'yyy',
        }
        user = User.from_dict(data)
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
                    u'created_ts': datetime.fromisoformat('2014-06-29T17:52:37.830000'),
                    u'id': ObjectId(),
                    u'salt': u'$NDNv1H1$foo$32$32$',
                    u'source': u'dashboard',
                }
            ],
        }
        user = User.from_dict(data)
        self.assertEqual(user.phone_numbers.primary.number, u'+22222222222')

    def test_user_tou_no_created_ts(self):
        """
        Basic test for user ToU.
        """
        tou_dict = {
            'event_id': ObjectId(),
            'event_type': 'tou_event',
            'version': '1',
            'created_by': 'unit test',
        }
        tou_events = ToUList([tou_dict])
        data = self.data1
        data.update({'tou': tou_events.to_list_of_dicts()})
        user = User.from_dict(data)
        # If we create the ToU from a dict w/o created_ts key, the created object will carry a _no_created_ts_in_db
        # attr set to True, and therefore the to_dict method will wipe out the created_ts key
        self.assertFalse(user.tou.has_accepted('1', reaccept_interval=94608000))  # reaccept_interval seconds (3 years)

    def test_user_tou(self):
        """
        Basic test for user ToU.
        """
        tou_dict = {
            'event_id': ObjectId(),
            'event_type': 'tou_event',
            'version': '1',
            'created_by': 'unit test',
            'created_ts': datetime.utcnow(),
        }
        tou_events = ToUList([tou_dict])
        data = self.data1
        data.update({'tou': tou_events.to_list_of_dicts()})
        user = User.from_dict(data)
        self.assertTrue(user.tou.has_accepted('1', reaccept_interval=94608000))  # reaccept_interval seconds (3 years)
        self.assertFalse(user.tou.has_accepted('2', reaccept_interval=94608000))  # reaccept_interval seconds (3 years)

    def test_locked_identity_load(self):
        locked_identity = {'created_by': 'test', 'identity_type': 'nin', 'number': '197801012345'}
        data = self.data1
        data['locked_identity'] = [locked_identity]
        user = User.from_dict(data)
        self.assertTrue(user.locked_identity)
        self.assertIsInstance(user.locked_identity.find('nin').created_by, string_types)
        self.assertIsInstance(user.locked_identity.find('nin').created_ts, datetime)
        self.assertIsInstance(user.locked_identity.find('nin').identity_type, string_types)
        self.assertIsInstance(user.locked_identity.find('nin').number, string_types)

    def test_locked_identity_set(self):
        locked_identity = {'created_by': 'test', 'identity_type': 'nin', 'number': '197801012345'}
        user = User.from_dict(self.data1)
        locked_nin = LockedIdentityNin.from_dict(
            dict(number=locked_identity['number'], created_by=locked_identity['created_by'],)
        )
        user.locked_identity.add(locked_nin)
        self.assertEqual(user.locked_identity.count, 1)

        locked_nin = user.locked_identity.find('nin')
        self.assertIsInstance(locked_nin.created_by, string_types)
        self.assertIsInstance(locked_nin.created_ts, datetime)
        self.assertIsInstance(locked_nin.identity_type, string_types)
        self.assertIsInstance(locked_nin.number, string_types)

    def test_locked_identity_to_dict(self):
        locked_identity = {'created_by': 'test', 'identity_type': 'nin', 'number': '197801012345'}
        user = User.from_dict(self.data1)
        locked_nin = LockedIdentityNin.from_dict(
            dict(number=locked_identity['number'], created_by=locked_identity['created_by'],)
        )
        user.locked_identity.add(locked_nin)

        old_user = User.from_dict(user.to_dict())
        self.assertEqual(user.locked_identity.count, 1)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].created_by, string_types)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].created_ts, datetime)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].identity_type, string_types)
        self.assertIsInstance(old_user.locked_identity.to_list()[0].number, string_types)

        new_user = User.from_dict(user.to_dict())
        self.assertEqual(user.locked_identity.count, 1)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].created_by, string_types)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].created_ts, datetime)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].identity_type, string_types)
        self.assertIsInstance(new_user.locked_identity.to_list()[0].number, string_types)

    def test_locked_identity_remove(self):
        locked_identity = {'created_by': 'test', 'identity_type': 'nin', 'number': '197801012345'}
        user = User.from_dict(self.data1)
        locked_nin = LockedIdentityNin.from_dict(
            dict(number=locked_identity['number'], created_by=locked_identity['created_by'],)
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
        id_token['created_by'] = 'test'
        oidc_id_token = OidcIdToken.from_dict(id_token)
        oidc_data['created_by'] = 'test'
        oidc_data['id_token'] = oidc_id_token
        oidc_authz = OidcAuthorization.from_dict(oidc_data)
        orcid_element = Orcid.from_dict(dict(id=orcid, oidc_authz=oidc_authz, created_by='test'))

        user = User.from_dict(self.data1)
        user.orcid = orcid_element

        old_user = User.from_dict(user.to_dict())
        self.assertIsNotNone(old_user.orcid)
        self.assertIsInstance(old_user.orcid.created_by, string_types)
        self.assertIsInstance(old_user.orcid.created_ts, datetime)
        self.assertIsInstance(old_user.orcid.id, string_types)
        self.assertIsInstance(old_user.orcid.oidc_authz, OidcAuthorization)
        self.assertIsInstance(old_user.orcid.oidc_authz.id_token, OidcIdToken)

        new_user = User.from_dict(user.to_dict())
        self.assertIsNotNone(new_user.orcid)
        self.assertIsInstance(new_user.orcid.created_by, string_types)
        self.assertIsInstance(new_user.orcid.created_ts, datetime)
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
            {'created_by': 'phone', 'number': '+4670999', 'primary': False, 'verified': False,},
        ]
        user = User.from_dict(
            data={
                '_id': ObjectId(),
                'eduPersonPrincipalName': 'test-test',
                'passwords': [],
                'mobile': [{'mobile': '+4673123', 'primary': True, 'verified': True}],
                'phone': phone,
            }
        )
        out = user.to_dict()['phone']

        assert phone == out, 'The phone objects differ when using both phone and mobile'

    def test_both_sn_and_surname(self):
        """ Test user that has both 'sn' and 'surname' """
        user = User.from_dict(
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


class TestUser(unittest.TestCase, _AbstractUserTestCase):
    def setUp(self):
        self.data1 = {
            u'_id': ObjectId('547357c3d00690878ae9b620'),
            u'eduPersonPrincipalName': u'guvat-nalif',
            u'mail': u'user@example.net',
            u'mailAliases': [
                {
                    u'added_timestamp': datetime.fromisoformat('2014-12-18T11:25:19.804000'),
                    u'email': u'user@example.net',
                    u'verified': True,
                    u'primary': True,
                }
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.fromisoformat('2014-11-24T16:22:49.188000'),
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
        self.user1 = User.from_dict(self.data1)

        self.data2 = {
            u'_id': ObjectId('549190b5d00690878ae9b622'),
            u'displayName': u'Some \xf6ne',
            u'eduPersonPrincipalName': u'birub-gagoz',
            u'givenName': u'Some',
            u'mail': u'some.one@gmail.com',
            u'mailAliases': [
                {u'email': u'someone+test1@gmail.com', u'verified': True},
                {
                    u'added_timestamp': datetime.fromisoformat('2014-12-17T14:35:14.728000'),
                    u'email': u'some.one@gmail.com',
                    u'verified': True,
                },
            ],
            u'phone': [
                {
                    u'created_ts': datetime.fromisoformat('2014-12-18T09:11:35.078000'),
                    u'number': u'+46702222222',
                    u'primary': True,
                    u'verified': True,
                }
            ],
            u'passwords': [
                {
                    u'created_ts': datetime.fromisoformat('2015-02-11T13:58:42.327000'),
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
                    'created_ts': datetime.fromisoformat('2020-02-04T17:42:33.696751'),
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
        self.user2 = User.from_dict(self.data2)

    def test_phone_numbers(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        to_dict_result = self.user2.phone_numbers.to_list_of_dicts()

        expected = self.data2['phone']
        obtained = to_dict_result

        assert obtained == expected


class TestNewUser(unittest.TestCase, _AbstractUserTestCase):
    def setUp(self):
        self._setup_user1()
        self._setup_user2()

    def _setup_user1(self):
        mailAliases_list = [
            MailAddress(
                created_ts=datetime.fromisoformat('2014-12-18T11:25:19.804000'),
                email='user@example.net',
                is_verified=True,
                is_primary=True,
            )
        ]
        password_list = [
            Password(
                created_ts=datetime.fromisoformat('2014-11-24T16:22:49.188000'),
                credential_id='54735b588a7d2a2c4ec3e7d0',
                salt='$NDNv1H1$315d7$32$32$',
                created_by='dashboard',
                is_generated=False,
            )
        ]

        nin_list = [
            Nin(
                number='197801012345',
                created_ts=datetime.fromisoformat('2014-11-24T16:22:49.188000'),
                is_verified=True,
                is_primary=True,
                created_by='dashboard',
            )
        ]
        self.user1 = User(
            user_id=ObjectId('547357c3d00690878ae9b620'),
            eppn='guvat-nalif',
            mail_addresses=MailAddressList(mailAliases_list),
            credentials=CredentialList(password_list),
            nins=NinList(nin_list),
            subject=SubjectType('physical person'),
            entitlements=[u'http://foo.example.org'],
            language='en',
        )

        self.data1 = self.user1.to_dict()

    def _setup_user2(self):
        mailAliases_list = [
            MailAddress(email='someone+test1@gmail.com', is_verified=True),
            MailAddress(
                email='some.one@gmail.com',
                created_ts=datetime.fromisoformat('2014-12-17T14:35:14.728000'),
                is_verified=True,
                is_primary=True,
            ),
        ]
        phone_list = [
            PhoneNumber(
                number='+46702222222',
                created_ts=datetime.fromisoformat('2014-12-18T09:11:35.078000'),
                is_primary=True,
                is_verified=True,
            )
        ]
        credential_list = [
            Password(
                created_ts=datetime.fromisoformat('2015-02-11T13:58:42.327000'),
                credential_id='54db60128a7d2a26e8690cda',
                salt='$NDNv1H1$db011fc$32$32$',
                is_generated=False,
                created_by='dashboard',
            ),
            U2F(
                version='U2F_V2',
                app_id='unit test',
                keyhandle='U2F SWAMID AL2',
                public_key='foo',
                is_verified=True,
                proofing_method=METHOD_SWAMID_AL2_MFA,
                proofing_version='testing',
            ),
        ]
        profile = Profile(
            created_by='test application',
            created_ts=datetime.fromisoformat('2020-02-04T17:42:33.696751'),
            owner='test owner 1',
            schema='test schema',
            profile_data={
                'a_string': 'I am a string',
                'an_int': 3,
                'a_list': ['eins', 2, 'drei'],
                'a_map': {'some': 'data'},
            },
        )

        self.user2 = User(
            user_id=ObjectId('549190b5d00690878ae9b622'),
            eppn='birub-gagoz',
            display_name='Some \xf6ne',
            given_name='Some',
            mail_addresses=MailAddressList(mailAliases_list),
            phone_numbers=PhoneNumberList(phone_list),
            credentials=CredentialList(credential_list),
            profiles=ProfileList([profile]),
            language='sv',
            surname='\xf6ne',
            subject=SubjectType('physical person'),
        )

        self.data2 = self.user2.to_dict()

    def test_mail_addresses_from_dict(self):
        """
        Test that we get back a correct list of dicts for old-style userdb data.
        """
        mailAliases_list = [
            {'email': 'someone+test1@gmail.com', 'verified': True},
            {
                'created_ts': datetime.fromisoformat('2014-12-17T14:35:14.728000'),
                'email': 'some.one@gmail.com',
                'verified': True,
                'primary': True,
            },
        ]
        mail_addresses = MailAddressList(mailAliases_list)

        to_dict_output = mail_addresses.to_list_of_dicts()

        # The {'email': 'someone+test1@gmail.com', 'verified': True} should've beem flagged as primary: False
        found = False
        for this in to_dict_output:
            if this['email'] == 'someone+test1@gmail.com':
                assert this['primary'] == False
                # now delete the marking from the to_list_of_dicts output to be able to compare it to the input below
                del this['primary']
                found = True
        assert found == True, 'The non-primary e-mail in the input dict was not marked as non-primary'

        assert to_dict_output == mailAliases_list

    def test_phone_numbers_from_dict(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        phone_list = [
            {
                'created_ts': datetime.fromisoformat('2014-12-18T09:11:35.078000'),
                'number': '+46702222222',
                'primary': True,
                'verified': True,
            }
        ]
        phone_numbers = PhoneNumberList(phone_list)
        to_dict_result = phone_numbers.to_list_of_dicts()
        assert to_dict_result == phone_list

    def test_passwords_from_dict(self):
        """
        Test that we get back a dict identical to the one we put in for old-style userdb data.
        """
        first = {
            'created_ts': datetime.fromisoformat('2015-02-11T13:58:42.327000'),
            'id': ObjectId('54db60128a7d2a26e8690cda'),
            'salt': '$NDNv1H1$db011fc$32$32$',
            'is_generated': False,
            'source': 'dashboard',
        }
        second = {
            'version': 'U2F_V2',
            'app_id': 'unit test',
            'keyhandle': 'U2F SWAMID AL2',
            'public_key': 'foo',
            'verified': True,
            'proofing_method': METHOD_SWAMID_AL2_MFA,
            'proofing_version': 'testing',
        }

        password_list = [first, second]
        passwords = CredentialList(password_list)

        to_dict_result = passwords.to_list_of_dicts()

        # adjust for expected changes
        first['created_by'] = first.pop('source')
        first['credential_id'] = str(first.pop('id'))
        second['description'] = ''

        expected = [first, second]

        assert to_dict_result == expected
