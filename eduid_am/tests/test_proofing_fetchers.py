# -*- coding: utf-8 -*-

from copy import deepcopy

import bson

from eduid_am.testing import AMTestCase
from eduid_userdb.exceptions import UserDoesNotExist
from eduid_userdb.personal_data import PersonalDataUser
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.reset_password import ResetPasswordUser
from eduid_userdb.security import SecurityUser
from eduid_userdb.testing import normalised_data

USER_DATA = {
    'givenName': 'Testaren',
    'surname': 'Testsson',
    'displayName': 'John',
    'preferredLanguage': 'sv',
    'eduPersonPrincipalName': 'test-test',
    'mailAliases': [{'email': 'john@example.com', 'verified': True,}],
    'mobile': [{'verified': True, 'mobile': '+46700011336', 'primary': True}],
    'passwords': [
        {
            'credential_id': '112345678901234567890123',
            'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
        }
    ],
    'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
    'orcid': {
        'oidc_authz': {
            'token_type': 'bearer',
            'refresh_token': 'a_refresh_token',
            'access_token': 'an_access_token',
            'id_token': {
                'nonce': 'a_nonce',
                'sub': 'sub_id',
                'iss': 'https://issuer.example.org',
                'created_by': 'orcid',
                'exp': 1526890816,
                'auth_time': 1526890214,
                'iat': 1526890216,
                'aud': ['APP-YIAD0N1L4B3Z3W9Q'],
            },
            'expires_in': 631138518,
            'created_by': 'orcid',
        },
        'given_name': 'Testaren',
        'family_name': 'Testsson',
        'name': None,
        'id': 'orcid_unique_id',
        'verified': True,
        'created_by': 'orcid',
    },
}


class ProofingTestCase(AMTestCase):
    def setUp(self):
        super().setUp()
        self.user_data = deepcopy(USER_DATA)

        # Copy all user documents from the AM database into the private database used
        # by _all_ the fetchers available through self.af_registry.
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser.from_dict(userdoc)
            for fetcher in self.af_registry.values():
                fetcher.private_db.save(proofing_user, check_sync=False)


class AttributeFetcherOldToNewUsersTests(ProofingTestCase):

    def test_invalid_user(self):
        for fetcher in self.af_registry:
            with self.assertRaises(UserDoesNotExist):
                fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):
        for fetcher in self.af_registry.values():
            proofing_user = ProofingUser.from_dict(self.user_data)
            fetcher.private_db.save(proofing_user)

            actual_update = fetcher.fetch_attrs(proofing_user.user_id)
            expected_update = {
                '$set': {
                    "givenName": u"Testaren",
                    "surname": u"Testsson",
                    "displayName": u"John",
                    'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                },
            }

            self.assertDictEqual(actual_update, expected_update)

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        for fetcher in self.af_registry.values():
            # Write bad entry into database
            result = fetcher.private_db._coll.insert_one(self.user_data)
            user_id = result.inserted_id

            with self.assertRaises(TypeError):
                fetcher.fetch_attrs(user_id)

    def test_fillup_attributes(self):

        for fetcher in self.af_registry.values():
            proofing_user = ProofingUser.from_dict(self.user_data)
            fetcher.private_db.save(proofing_user)

            actual_update = fetcher.fetch_attrs(proofing_user.user_id)
            expected_update = {
                '$set': {
                    "givenName": u"Testaren",
                    "surname": u"Testsson",
                    "displayName": u"John",
                    'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                },
            }

            self.assertDictEqual(actual_update, expected_update)

    def test_append_attributes_letter_proofing_data(self):
        self.maxDiff = None
        self.user_data.update(
            {
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code 1",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            "OfficialAddress": {
                                "PostalCode": u"12345",
                                "City": u"LANDET",
                                "Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            "Name": {"Surname": u"Testsson", "GivenName": u"Testaren Test", "GivenNameMarking": u"20"},
                        },
                        "number": u"123456781235",
                        "created_by": u"eduid-idproofing-letter",
                        "verified_ts": u'ts',
                        "transaction_id": u"debug mode transaction id",
                    }
                ],
            }
        )
        proofing_user = ProofingUser.from_dict(self.user_data)
        fetcher = self.af_registry['eduid_letter_proofing']
        fetcher.private_db.save(proofing_user)

        fetched1 = fetcher.fetch_attrs(proofing_user.user_id)

        expected1 = {
            '$set': {
                "givenName": u"Testaren",
                "surname": u"Testsson",
                "displayName": u"John",
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code 1",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20",
                            },
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id",
                    }
                ],
            },
        }

        assert normalised_data(fetched1) == expected1, 'Fetched (old to new) letter proofing data has unexpected data'

        actual_update = fetcher.fetch_attrs(proofing_user.user_id)

        # Don't repeat the letter_proofing_data if invoked twice on the same input
        assert normalised_data(actual_update) == expected1, 'Fetched (old to new, 2nd time) letter proofing data has unexpected data'

        # Adding a new letter_proofing_data
        self.user_data['letter_proofing_data'].append(
            {
                "verification_code": "secret code 2",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": 'ts',
                "official_address": {
                    "OfficialAddress": {"PostalCode": "12345", "City": "LANDET", "Address2": "ÖRGATAN 79 LGH 10"},
                    "Name": {"Surname": "Testsson", "GivenName": "Testaren Test", "GivenNameMarking": "20"},
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": 'ts',
                "transaction_id": "debug mode transaction id",
            }
        )
        proofing_user = ProofingUser.from_dict(self.user_data)
        fetcher.private_db.save(proofing_user)

        fetched2 = fetcher.fetch_attrs(proofing_user.user_id)

        expected2 = {
            '$set': {
                "givenName": u"Testaren",
                "surname": u"Testsson",
                "displayName": u"John",
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        u"verification_code": u"secret code 1",
                        u"verified": True,
                        u"verified_by": u"eduid-idproofing-letter",
                        u"created_ts": u'ts',
                        u"official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20",
                            },
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id",
                    },
                    {
                        u"verification_code": u"secret code 2",
                        u"verified": True,
                        u"verified_by": u"eduid-idproofing-letter",
                        u"created_ts": u'ts',
                        u"official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20",
                            },
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id",
                    },
                ],
            },
        }

        assert (
            normalised_data(fetched2) == expected2
        ), 'Fetched (old to new) letter proofing data with appended attributes has unexpected data'

    def convert_and_remove_norEduPersonNIN(self):
        self.user_data.update({'norEduPersonNIN': '123456781235'})
        del self.user_data['nins']
        for fetcher in self.af_registry.values():
            proofing_user = ProofingUser.from_dict(self.user_data)
            fetcher.private_db.save(proofing_user)

            actual_update = fetcher.fetch_attrs(proofing_user.user_id)
            expected_update = {
                '$set': {'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],},
                '$unset': {'norEduPersonNIN': None},
            }

            self.assertDictEqual(actual_update, expected_update)


class AttributeFetcherNINProofingTests(ProofingTestCase):

    def test_invalid_user(self):
        for fetcher in self.af_registry.values():
            with self.assertRaises(UserDoesNotExist):
                fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):

        for fetcher in self.af_registry.values():
            proofing_user = ProofingUser.from_dict(self.user_data)
            fetcher.private_db.save(proofing_user)

            self.assertDictEqual(
                fetcher.fetch_attrs(proofing_user.user_id),
                {
                    '$set': {
                        "givenName": u"Testaren",
                        "surname": u"Testsson",
                        "displayName": u"John",
                        'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
                    },
                },
            )

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        for fetcher in self.af_registry.values():
            # Write bad entry into database
            result = fetcher.private_db._coll.insert_one(self.user_data)
            user_id = result.inserted_id

            with self.assertRaises(TypeError):
                fetcher.fetch_attrs(user_id)

    def test_fillup_attributes(self):

        for fetcher in self.af_registry.values():
            proofing_user = ProofingUser.from_dict(self.user_data)
            fetcher.private_db.save(proofing_user)

            self.assertDictEqual(
                fetcher.fetch_attrs(proofing_user.user_id),
                {
                    '$set': {
                        "givenName": u"Testaren",
                        "surname": u"Testsson",
                        "displayName": u"John",
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                    },
                },
            )

    def test_append_attributes_letter_proofing_data(self):
        self.user_data.update(
            {
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            "OfficialAddress": {
                                "PostalCode": u"12345",
                                "City": u"LANDET",
                                "Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            "Name": {"Surname": u"Testsson", "GivenName": u"Testaren Test", "GivenNameMarking": u"20"},
                        },
                        "number": u"123456781235",
                        "created_by": u"eduid-idproofing-letter",
                        "verified_ts": u'ts',
                        "transaction_id": u"debug mode transaction id",
                    }
                ],
            }
        )
        proofing_user = ProofingUser.from_dict(self.user_data)
        fetcher = self.af_registry['eduid_letter_proofing']
        fetcher.private_db.save(proofing_user)

        fetched = fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            '$set': {
                "givenName": u"Testaren",
                "surname": u"Testsson",
                "displayName": u"John",
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        u"verification_code": u"secret code",
                        u"verified": True,
                        u"verified_by": u"eduid-idproofing-letter",
                        u"created_ts": u'ts',
                        u"official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20",
                            },
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id",
                    }
                ],
            },
        }

        assert normalised_data(fetched) == expected, 'Fetched letter proofing data has unexpected data'

        fetched2 = fetcher.fetch_attrs(proofing_user.user_id)

        # Don't repeat the letter_proofing_data
        assert normalised_data(fetched2) == expected, 'Fetched (2nd time) letter proofing data has unexpected data'

        # Adding a new letter_proofing_data
        self.user_data['letter_proofing_data'].append(
            {
                "verification_code": "secret code",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": 'ts',
                "official_address": {
                    "OfficialAddress": {"PostalCode": "12345", "City": "LANDET", "Address2": "ÖRGATAN 79 LGH 10"},
                    "Name": {"Surname": "Testsson", "GivenName": "Testaren Test", "GivenNameMarking": "20"},
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": 'ts',
                "transaction_id": "debug mode transaction id",
            }
        )
        proofing_user = ProofingUser.from_dict(self.user_data)
        fetcher.private_db.save(proofing_user)

        fetched3 = fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            '$set': {
                "givenName": u"Testaren",
                "surname": u"Testsson",
                "displayName": u"John",
                'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                "letter_proofing_data": [
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20",
                            },
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id",
                    },
                    {
                        "verification_code": u"secret code",
                        "verified": True,
                        "verified_by": u"eduid-idproofing-letter",
                        "created_ts": u'ts',
                        "official_address": {
                            u"OfficialAddress": {
                                u"PostalCode": u"12345",
                                u"City": u"LANDET",
                                u"Address2": u"ÖRGATAN 79 LGH 10",
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20",
                            },
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id",
                    },
                ],
            },
        }

        assert normalised_data(fetched3) == expected, 'Fetched letter proofing data with appended attributes has unexpected data'


class AttributeFetcherEmailProofingTests(ProofingTestCase):

    def test_invalid_user(self):
        fetcher = self.af_registry['eduid_email']
        with self.assertRaises(UserDoesNotExist):
            fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):

        fetcher = self.af_registry['eduid_email']
        proofing_user = ProofingUser.from_dict(self.user_data)
        fetcher.private_db.save(proofing_user)

        fetched = fetcher.fetch_attrs(proofing_user.user_id)
        expected = {
            '$set': {'mailAliases': [{'email': 'john@example.com', 'verified': True, 'primary': True,}],},
        }

        assert normalised_data(fetched) == expected

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        fetcher = self.af_registry['eduid_email']
        # Write bad entry into database
        result = fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            fetcher.fetch_attrs(user_id)

    def test_fillup_attributes(self):
        self.user_data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{'email': 'john@example.com', 'verified': True, 'primary': True}],
            'mobile': [{'verified': True, 'mobile': '+46700011336', 'primary': True}],
            'passwords': [
                {
                    'id': bson.ObjectId('112345678901234567890123'),
                    'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                }
            ],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        fetcher = self.af_registry['eduid_email']
        proofing_user = ProofingUser.from_dict(self.user_data)
        fetcher.private_db.save(proofing_user)

        fetched = fetcher.fetch_attrs(proofing_user.user_id)
        expected = {
            '$set': {'mailAliases': [{'email': 'john@example.com', 'verified': True, 'primary': True}],},
        }

        assert normalised_data(fetched) == expected


class AttributeFetcherPhoneProofingTests(ProofingTestCase):

    def setUp(self):
        super().setUp()
        self.fetcher = self.af_registry['eduid_phone']

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):
        proofing_user = ProofingUser.from_dict(self.user_data)
        self.fetcher.private_db.save(proofing_user)
        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            '$set': {'phone': [{'verified': True, 'number': '+46700011336', 'primary': True}],},
        }

        assert normalised_data(fetched) == expected, 'Unexpected data fetched by phone fetcher for existing user'

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        # Write bad entry into database
        result = self.fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            self.fetcher.fetch_attrs(user_id)


class AttributeFetcherPersonalDataTests(ProofingTestCase):
    def setUp(self):
        super().setUp()
        self.fetcher = self.af_registry['eduid_personal_data']

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):
        personal_data_user = PersonalDataUser.from_dict(self.user_data)
        self.fetcher.private_db.save(personal_data_user)

        self.assertDictEqual(
            self.fetcher.fetch_attrs(personal_data_user.user_id),
            {
                '$set': {
                    'givenName': u'Testaren',
                    'surname': u'Testsson',
                    'displayName': u'John',
                    'preferredLanguage': u'sv',
                },
            },
        )

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        # Write bad entry into database
        result = self.fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            self.fetcher.fetch_attrs(user_id)

    def test_fillup_attributes(self):
        personal_data_user = PersonalDataUser.from_dict(self.user_data)
        self.fetcher.private_db.save(personal_data_user)

        self.assertDictEqual(
            self.fetcher.fetch_attrs(personal_data_user.user_id),
            {
                '$set': {
                    'givenName': 'Testaren',
                    'surname': 'Testsson',
                    'displayName': 'John',
                    'preferredLanguage': 'sv',
                },
            },
        )


class AttributeFetcherSecurityTests(ProofingTestCase):
    def setUp(self):
        super().setUp()
        self.fetcher = self.af_registry['eduid_security']

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):
        security_user = SecurityUser.from_dict(self.user_data)
        self.fetcher.private_db.save(security_user)

        expected = {
            '$set': {
                'passwords': [
                    {
                        'credential_id': u'112345678901234567890123',
                        'is_generated': False,
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }
                ],
                'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
                'phone': [{'number': '+46700011336', 'primary': True, 'verified': True}],
            },
            '$unset': {'terminated': None},
        }
        fetched = self.fetcher.fetch_attrs(security_user.user_id)

        assert normalised_data(fetched) == expected

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        # Write bad entry into database
        result = self.fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            self.fetcher.fetch_attrs(user_id)

    def test_fillup_attributes(self):
        security_user = SecurityUser.from_dict(self.user_data)
        self.fetcher.private_db.save(security_user)

        fetched = self.fetcher.fetch_attrs(security_user.user_id)

        expected = {
            '$set': {
                'passwords': [
                    {
                        'credential_id': u'112345678901234567890123',
                        'is_generated': False,
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }
                ],
                'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
                'phone': [{'number': '+46700011336', 'primary': True, 'verified': True}],
            },
            '$unset': {'terminated': None},
        }
        assert normalised_data(fetched) == expected


class AttributeFetcherResetPasswordTests(ProofingTestCase):
    def setUp(self):
        super().setUp()
        self.fetcher = self.af_registry['eduid_reset_password']

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):
        reset_password_user = ResetPasswordUser.from_dict(self.user_data)
        self.fetcher.private_db.save(reset_password_user)

        fetched = self.fetcher.fetch_attrs(reset_password_user.user_id)

        expected = {
            '$set': {
                'passwords': [
                    {
                        'credential_id': u'112345678901234567890123',
                        'is_generated': False,
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }
                ],
                'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
                'phone': [{'number': '+46700011336', 'primary': True, 'verified': True}],
            }
        }

        assert normalised_data(fetched) == expected, 'Wrong data fetched by reset password fetcher'

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        # Write bad entry into database
        result = self.fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            self.fetcher.fetch_attrs(user_id)

    def test_fillup_attributes(self):
        reset_password_user = ResetPasswordUser.from_dict(self.user_data)
        self.fetcher.private_db.save(reset_password_user)

        fetched = self.fetcher.fetch_attrs(reset_password_user.user_id)

        expected = {
            '$set': {
                'passwords': [
                    {
                        'credential_id': u'112345678901234567890123',
                        'is_generated': False,
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }
                ],
                'nins': [{'number': '123456781235', 'primary': True, 'verified': True}],
                'phone': [{'number': '+46700011336', 'primary': True, 'verified': True}],
            }
        }

        assert normalised_data(fetched) == expected, 'Wrong data fetched by reset password fetcher'


class AttributeFetcherOrcidTests(ProofingTestCase):
    def setUp(self):
        super().setUp()
        self.fetcher = self.af_registry['eduid_orcid']

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('0' * 24))

    def test_existing_user(self):
        proofing_user = ProofingUser.from_dict(self.user_data)
        self.fetcher.private_db.save(proofing_user)
        fetched = self.fetcher.fetch_attrs(proofing_user.user_id)

        expected = {
            '$set': {
                'orcid': {
                    'oidc_authz': {
                        'token_type': 'bearer',
                        'refresh_token': 'a_refresh_token',
                        'access_token': 'an_access_token',
                        'id_token': {
                            'nonce': 'a_nonce',
                            'sub': 'sub_id',
                            'iss': 'https://issuer.example.org',
                            'created_by': 'orcid',
                            'exp': 1526890816,
                            'auth_time': 1526890214,
                            'iat': 1526890216,
                            'aud': ['APP-YIAD0N1L4B3Z3W9Q'],
                        },
                        'expires_in': 631138518,
                        'created_by': 'orcid',
                    },
                    'name': None,
                    'given_name': 'Testaren',
                    'family_name': 'Testsson',
                    'verified': True,
                    'id': 'orcid_unique_id',
                    'created_by': 'orcid',
                }
            },
        }

        assert normalised_data(fetched) == expected

    def test_malicious_attributes(self):
        self.user_data.update(
            {'malicious': 'hacker',}
        )

        # Write bad entry into database
        result = self.fetcher.private_db._coll.insert_one(self.user_data)
        user_id = result.inserted_id

        with self.assertRaises(TypeError):
            self.fetcher.fetch_attrs(user_id)

    def test_remove_orcid(self):
        proofing_user = ProofingUser.from_dict(self.user_data)
        proofing_user.orcid = None
        self.fetcher.private_db.save(proofing_user)

        self.assertDictEqual(self.fetcher.fetch_attrs(proofing_user.user_id), {'$unset': {'orcid': None}})
