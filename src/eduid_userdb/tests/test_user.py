from bson import ObjectId
import datetime

from unittest import TestCase

from eduid_userdb.user import User
from eduid_userdb.exceptions import UserHasUnknownData, UserHasNotCompletedSignup, UserIsRevoked

__author__ = 'ft'


class TestUser(TestCase):

    def setUp(self):
        self.data1 = {u'_id': ObjectId('547357c3d00690878ae9b620'),
                      u'eduPersonPrincipalName': u'guvat-nalif',
                      u'mail': u'user@example.net',
                      u'mailAliases': [{u'added_timestamp': datetime.datetime(2014, 12, 18, 11, 25, 19, 804000),
                                        u'email': u'user@example.net',
                                        u'verified': True}],
                      u'passwords': [{u'created_ts': datetime.datetime(2014, 11, 24, 16, 22, 49, 188000),
                                      u'id': ObjectId('54735b588a7d2a2c4ec3e7d0'),
                                      u'salt': u'$NDNv1H1$315d7$32$32$',
                                      u'source': u'dashboard'}],
                      u'norEduPersonNIN': [u'197801012345'],
                      u'subject': u'physical person',
                      u'eduPersonEntitlement': [u'http://foo.example.org'],
                      u'preferredLanguage': u'en',
                      }
        self.user1 = User(self.data1)

        self.data2 = {u'_id': ObjectId('549190b5d00690878ae9b622'),
                      u'displayName': u'Some \xf6ne',
                      u'eduPersonPrincipalName': u'birub-gagoz',
                      u'givenName': u'Some',
                      u'mail': u'some.one@gmail.com',
                      u'mailAliases': [{u'email': u'someone+test1@gmail.com',
                                        u'verified': True},
                                       {u'added_timestamp': datetime.datetime(2014, 12, 17, 14, 35, 14, 728000),
                                        u'email': u'some.one@gmail.com',
                                        u'verified': True}],
                      u'mobile': [{u'added_timestamp': datetime.datetime(2014, 12, 18, 9, 11, 35, 78000),
                                   u'mobile': u'+46702222222',
                                   u'primary': True,
                                   u'verified': True}],
                      u'passwords': [{u'created_ts': datetime.datetime(2015, 2, 11, 13, 58, 42, 327000),
                                      u'id': ObjectId('54db60128a7d2a26e8690cda'),
                                      u'salt': u'$NDNv1H1$db011fc$32$32$',
                                      u'source': u'dashboard'}],
                      u'preferredLanguage': u'sv',
                      u'sn': u'\xf6ne',
                      u'subject': u'physical person'}
        self.user2 = User(self.data2)

    def test_user_id(self):
        self.assertEqual(self.user1.user_id, self.data1['_id'])

    def test_eppn(self):
        self.assertEqual(self.user1.eppn, self.data1['eduPersonPrincipalName'])

    def test_given_name(self):
        self.assertEqual(self.user2.given_name, self.data2['givenName'])

    def test_display_name(self):
        self.assertEqual(self.user2.display_name, self.data2['displayName'])

    def test_surname(self):
        self.assertEqual(self.user2.surname, self.data2['sn'])

    def test_mail_addresses(self):
        self.assertEqual(self.user1.mail_addresses.primary.email, self.data1['mailAliases'][0]['email'])

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
        user = User(data)
        self.assertEqual(self.user1._data, user._data)

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
        data = {u'_id': ObjectId(),
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
        data[u'sn'] = 'not signup-incomplete anymore'
        data[u'passwords'] = [{u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                                u'id': ObjectId(),
                                u'salt': u'salt',
                                u'source': u'dashboard'}]
        user = User(data)
        self.assertEqual(user.surname, data['sn'])

    def test_revoked_user(self):
        """
        Test ability to identify revoked users.
        """
        data = {u'_id': ObjectId(),
                u'eduPersonPrincipalName': u'binib-mufus',
                u'revoked_ts': datetime.datetime(2015, 5, 26, 8, 33, 56, 826000),
                }
        with self.assertRaises(UserIsRevoked):
            User(data)

    def test_user_with_no_primary_mail(self):
        mail = u'yahoo@example.com'
        data = {u'_id': ObjectId(),
                u'eduPersonPrincipalName': u'lutol-bafim',
                u'mailAliases': [{u'email': mail, u'verified': True}],
                u'passwords': [{u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                                u'id': ObjectId(),
                                u'salt': u'salt',
                                u'source': u'dashboard'}],
                }
        user = User(data)
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_user_with_indirectly_verified_primary_mail(self):
        """
        If a user has passwords set, the 'mail' attribute will be considered indirectly verified.
        """
        mail = u'yahoo@example.com'
        data = {u'_id': ObjectId(),
                u'eduPersonPrincipalName': u'lutol-bafim',
                u'mail': mail,
                u'mailAliases': [{u'email': mail, u'verified': False}],
                u'passwords': [{u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                                u'id': ObjectId(),
                                u'salt': u'salt',
                                u'source': u'dashboard'}],
                }
        user = User(data)
        self.assertEqual(mail, user.mail_addresses.primary.email)

    def test_user_with_csrf_junk_in_mail_address(self):
        """
        For a long time, Dashboard leaked CSRF tokens into the mail address dicts.
        """
        mail = u'yahoo@example.com'
        data = {u'_id': ObjectId(),
                u'eduPersonPrincipalName': u'test-test',
                u'mailAliases': [{u'email': mail,
                u'verified': True,
                u'csrf': u'6ae1d4e95305b72318a683883e70e3b8e302cd75'}],
                u'passwords': [{u'created_ts': datetime.datetime(2014, 9, 4, 8, 57, 7, 362000),
                                u'id': ObjectId(),
                                u'salt': u'salt',
                                u'source': u'dashboard'}],
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
        Test that the first entry in the `mobile' list is chosen as primary when none are verified.
        """
        number1 = u'+9112345678'
        number2 = u'+9123456789'
        data = {u'_id': ObjectId(),
                u'displayName': u'xxx yyy',
                u'eduPersonPrincipalName': u'pohig-test',
                u'givenName': u'xxx',
                u'mail': u'test@gmail.com',
                u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
                u'mobile': [{u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                             u'mobile': number1,
                             u'primary': False,
                             u'verified': False},
                            {u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                             u'mobile': number2,
                             u'primary': False,
                             u'verified': False}],
                u'passwords': [{u'created_ts': datetime.datetime(2014, 6, 29, 17, 52, 37, 830000),
                                u'id': ObjectId(),
                                u'salt': u'$NDNv1H1$foo$32$32$',
                                u'source': u'dashboard'}],
                u'preferredLanguage': u'en',
                u'sn': u'yyy',
                }
        user = User(data)
        self.assertEqual(user.phone_numbers.primary.number, number1)

    def test_two_non_primary_phones(self):
        """
        Test that the first verified number is chosen as primary, if there is a verified number.
        """
        number1 = u'+9112345678'
        number2 = u'+9123456789'
        data = {u'_id': ObjectId(),
                u'displayName': u'xxx yyy',
                u'eduPersonPrincipalName': u'pohig-test',
                u'givenName': u'xxx',
                u'mail': u'test@gmail.com',
                u'mailAliases': [{u'email': u'test@gmail.com', u'verified': True}],
                u'mobile': [{u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                             u'mobile': number1,
                             u'primary': False,
                             u'verified': False},
                            {u'csrf': u'47d42078719b8377db622c3ff85b94840b483c92',
                             u'mobile': number2,
                             u'primary': False,
                             u'verified': True}],
                u'passwords': [{u'created_ts': datetime.datetime(2014, 6, 29, 17, 52, 37, 830000),
                                u'id': ObjectId(),
                                u'salt': u'$NDNv1H1$foo$32$32$',
                                u'source': u'dashboard'}],
                u'preferredLanguage': u'en',
                u'sn': u'yyy',
                }
        user = User(data)
        self.assertEqual(user.phone_numbers.primary.number, number2)
