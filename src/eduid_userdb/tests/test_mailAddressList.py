from unittest import TestCase

import eduid_userdb.exceptions
import eduid_userdb.primaryelement
from eduid_userdb.mail import MailAddress, MailAddressList

__author__ = 'ft'


class TestMailAddressList(TestCase):

    def setUp(self):
        self.empty = MailAddressList([])

        self._one_dict = \
            [{'email': 'ft@one.example.org',
              'primary': True,
              'verified': True,
              }]
        self.one = MailAddressList(self._one_dict)

        self._two_dict = self._one_dict + \
            [{'email': 'ft@two.example.org',
               'primary': False,
               'verified': True,
               }]
        self.two = MailAddressList(self._two_dict)

        self._three_dict = self._two_dict + \
            [{'email': 'ft@three.example.org',
               'primary': False,
               'verified': False,
               },
              ]
        self.three = MailAddressList(self._three_dict)

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        self.assertEqual(self._one_dict, self.one.to_list_of_dicts())

    def test_find(self):
        match = self.one.find('ft@one.example.org')
        self.assertIsInstance(match, MailAddress)
        self.assertEqual(match.email, 'ft@one.example.org')
        self.assertEqual(match.is_verified, True)
        self.assertEqual(match.verified_ts, None)

    def test_add(self):
        second = self.two.find('ft@two.example.org')
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_duplicate(self):
        dup = self.two.find(self.two.primary.email)
        with self.assertRaises(eduid_userdb.primaryelement.DuplicatePrimaryElementViolation):
            self.two.add(dup)

    def test_add_another_primary(self):
        new = eduid_userdb.mail.address_from_dict({'email': 'ft@primary.example.org',
                                                   'verified': True,
                                                   'primary': True,
                                                   })
        with self.assertRaises(eduid_userdb.primaryelement.PrimaryElementViolation):
            self.one.add(new)

    def test_update(self):
        #self.fail()
        return

    def test_remove(self):
        now_two = self.three.remove('ft@three.example.org')
        self.assertEqual(self._two_dict, now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('foo@no-such-address.example.org')

    def test_remove_primary(self):
        with self.assertRaises(eduid_userdb.primaryelement.PrimaryElementViolation):
            self.two.remove(self.two.primary.email)

    def test_remove_primary_single(self):
        now_empty = self.one.remove(self.one.primary.email)
        self.assertEqual([], now_empty.to_list())

    def test_primary(self):
        match = self.one.primary
        self.assertEqual(match.email, 'ft@one.example.org')

    def test_set_primary_to_same(self):
        match = self.one.primary
        self.one.primary = match.email

        match = self.two.primary
        self.two.primary = match.email

    def test_set_unknown_as_primary(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.primary = 'foo@no-such-address.example.org'

    def test_set_unverified_as_primary(self):
        with self.assertRaises(eduid_userdb.primaryelement.PrimaryElementViolation):
            self.three.primary = 'ft@three.example.org'

    def test_change_primary(self):
        match = self.two.primary
        self.assertEqual(match.email, 'ft@one.example.org')
        self.two.primary = 'ft@two.example.org'
        updated = self.two.primary
        self.assertEqual(updated.email, 'ft@two.example.org')

