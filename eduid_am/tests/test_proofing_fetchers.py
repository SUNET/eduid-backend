# -*- coding: utf-8 -*-

import bson
from copy import deepcopy

from eduid_userdb.exceptions import UserDoesNotExist, UserHasUnknownData
from eduid_userdb.testing import MongoTestCase
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.personal_data import PersonalDataUser
from eduid_userdb.security import SecurityUser
from eduid_proofing_amp import attribute_fetcher, oidc_plugin_init, letter_plugin_init, lookup_mobile_plugin_init
from eduid_proofing_amp import email_plugin_init, phone_plugin_init, personal_data_plugin_init, security_plugin_init
from eduid_proofing_amp import orcid_plugin_init

USER_DATA = {
    'givenName': 'Testaren',
    'surname': 'Testsson',
    'displayName': 'John',
    'preferredLanguage': 'sv',
    'eduPersonPrincipalName': 'test-test',
    'mailAliases': [{
        'email': 'john@example.com',
        'verified': True,
    }],
    'mobile': [{
        'verified': True,
        'mobile': '+46700011336',
        'primary': True
    }],
    'passwords': [{
        'credential_id': '112345678901234567890123',
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
    }],
    'nins': [
        {'number': '123456781235', 'primary': True, 'verified': True}
    ],
    'orcid': {
        'oidc_authz': {
            'token_type': 'bearer',
            'refresh_token': 'a_refresh_token',
            'access_token': 'an_access_token',
            'id_token': {
                    'nonce': 'a_nonce',
                    'sub': 'sub_id',
                    'iss': 'https://issuer.example.org',
                    'created_by' : 'orcid',
                    'exp': 1526890816,
                    'auth_time' : 1526890214,
                    'iat': 1526890216,
                    'aud': [
                            'APP-YIAD0N1L4B3Z3W9Q'
                    ]
            },
            'expires_in': 631138518,
            'created_by': 'orcid'
        },
        'given_name': 'Testaren',
        'family_name': 'Testsson',
        'name': None,
        'id': 'orcid_unique_id',
        'verified': True,
        'created_by': 'orcid'
    }
}


class AttributeFetcherOldToNewUsersTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherOldToNewUsersTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            oidc_plugin_init(self.am_settings),
            letter_plugin_init(self.am_settings),
            lookup_mobile_plugin_init(self.am_settings)
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.private_db.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherOldToNewUsersTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            actual_update = attribute_fetcher(context, proofing_user.user_id)
            expected_update = {
                    '$set': {
                        "givenName": u"Testaren",
                        "surname": u"Testsson",
                        "displayName": u"John",
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                    },
                }

            self.assertDictEqual(
                actual_update,
                expected_update
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            actual_update = attribute_fetcher(context, proofing_user.user_id)
            expected_update = {
                '$set': {
                    "givenName": u"Testaren",
                    "surname": u"Testsson",
                    "displayName": u"John",
                    'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                },
            }

            self.assertDictEqual(
                actual_update,
                expected_update
            )

    def test_append_attributes_letter_proofing_data(self):
        self.maxDiff = None
        self.user_data.update({
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
                            "Address2": u"ÖRGATAN 79 LGH 10"
                        },
                        "Name": {
                            "Surname": u"Testsson",
                            "GivenName": u"Testaren Test",
                            "GivenNameMarking": u"20"
                        }
                    },
                    "number": u"123456781235",
                    "created_by": u"eduid-idproofing-letter",
                    "verified_ts": u'ts',
                    "transaction_id": u"debug mode transaction id"
                }
            ],
        })
        proofing_user = ProofingUser(data=self.user_data)
        letter_plugin_context = letter_plugin_init(self.am_settings)
        letter_plugin_context.private_db.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
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
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    }
                ]
            },
        }
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)

        # Don't repeat the letter_proofing_data
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        # Adding a new letter_proofing_data
        self.user_data['letter_proofing_data'].append(
            {
                "verification_code": "secret code 2",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": 'ts',
                "official_address": {
                    "OfficialAddress": {
                        "PostalCode": "12345",
                        "City": "LANDET",
                        "Address2": "ÖRGATAN 79 LGH 10"
                    },
                    "Name": {
                        "Surname": "Testsson",
                        "GivenName": "Testaren Test",
                        "GivenNameMarking": "20"
                    }
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": 'ts',
                "transaction_id": "debug mode transaction id"
            }
        )
        proofing_user = ProofingUser(data=self.user_data)
        letter_plugin_context.private_db.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
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
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
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
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    },
                ]
            },
        }

        self.assertDictEqual(
            actual_update,
            expected_update
        )

    def convert_and_remove_norEduPersonNIN(self):
        self.user_data.update({'norEduPersonNIN': '123456781235'})
        del self.user_data['nins']
        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            actual_update = attribute_fetcher(context, proofing_user.user_id)
            expected_update = {
                '$set': {
                    'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                },
                '$unset': {
                    'norEduPersonNIN': None
                }
            }

            self.assertDictEqual(
                actual_update,
                expected_update
            )


class AttributeFetcherNINProofingTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherNINProofingTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            oidc_plugin_init(self.am_settings),
            letter_plugin_init(self.am_settings),
            lookup_mobile_plugin_init(self.am_settings)
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.private_db.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherNINProofingTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        "givenName": u"Testaren",
                        "surname": u"Testsson",
                        "displayName": u"John",
                        'nins': [
                            {'number': '123456781235', 'primary': True, 'verified': True}
                        ]
                    },
                }
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        "givenName": u"Testaren",
                        "surname": u"Testsson",
                        "displayName": u"John",
                        'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
                    },
                }
            )

    def test_append_attributes_letter_proofing_data(self):
        self.maxDiff = None
        self.user_data.update({
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
                            "Address2": u"ÖRGATAN 79 LGH 10"
                        },
                        "Name": {
                            "Surname": u"Testsson",
                            "GivenName": u"Testaren Test",
                            "GivenNameMarking": u"20"
                        }
                    },
                    "number": u"123456781235",
                    "created_by": u"eduid-idproofing-letter",
                    "verified_ts": u'ts',
                    "transaction_id": u"debug mode transaction id"
                }
            ],
        })
        proofing_user = ProofingUser(data=self.user_data)
        letter_plugin_context = letter_plugin_init(self.am_settings)
        letter_plugin_context.private_db.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
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
                                        u"Address2": u"ÖRGATAN 79 LGH 10"
                                    },
                                    u"Name": {
                                        u"Surname": u"Testsson",
                                        u"GivenName": u"Testaren Test",
                                        u"GivenNameMarking": u"20"
                                    }
                                },
                                u"number": u"123456781235",
                                u"created_by": u"eduid-idproofing-letter",
                                u"verified_ts": u'ts',
                                u"transaction_id": u"debug mode transaction id"
                            }
                        ]
                    },
                }

        self.assertDictEqual(
            actual_update,
            expected_update
        )

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)

        # Don't repeat the letter_proofing_data
        self.assertDictEqual(
            actual_update,
            expected_update
        )

        # Adding a new letter_proofing_data
        self.user_data['letter_proofing_data'].append(
            {
                "verification_code": "secret code",
                "verified": True,
                "verified_by": "eduid-idproofing-letter",
                "created_ts": 'ts',
                "official_address": {
                    "OfficialAddress": {
                        "PostalCode": "12345",
                        "City": "LANDET",
                        "Address2": "ÖRGATAN 79 LGH 10"
                    },
                    "Name": {
                        "Surname": "Testsson",
                        "GivenName": "Testaren Test",
                        "GivenNameMarking": "20"
                    }
                },
                "number": "123456781235",
                "created_by": "eduid-idproofing-letter",
                "verified_ts": 'ts',
                "transaction_id": "debug mode transaction id"
            }
        )
        proofing_user = ProofingUser(data=self.user_data)
        letter_plugin_context.private_db.save(proofing_user)

        actual_update = attribute_fetcher(letter_plugin_context, proofing_user.user_id)
        expected_update = {
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
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
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
                                u"Address2": u"ÖRGATAN 79 LGH 10"
                            },
                            u"Name": {
                                u"Surname": u"Testsson",
                                u"GivenName": u"Testaren Test",
                                u"GivenNameMarking": u"20"
                            }
                        },
                        u"number": u"123456781235",
                        u"created_by": u"eduid-idproofing-letter",
                        u"verified_ts": u'ts',
                        u"transaction_id": u"debug mode transaction id"
                    }
                ]
            },
        }

        self.assertDictEqual(
            actual_update,
            expected_update
        )


class AttributeFetcherEmailProofingTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherEmailProofingTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            email_plugin_init(self.am_settings),
        ]
        #for userdoc in self.amdb._get_all_docs():
        #    proofing_user = ProofingUser(data=userdoc)
        #    for context in self.plugin_contexts:
        #        context.private_db.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherEmailProofingTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'mailAliases': [{
                            'email': 'john@example.com',
                            'verified': True,
                            'primary': True,
                        }],
                    },
                }
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        self.user_data = {
            'givenName': 'Testaren',
            'surname': 'Testsson',
            'preferredLanguage': 'sv',
            'eduPersonPrincipalName': 'test-test',
            'displayName': 'John',
            'mailAliases': [{
                'email': 'john@example.com',
                'verified': True,
                'primary': True
            }],
            'mobile': [{
                'verified': True,
                'mobile': '+46700011336',
                'primary': True
            }],
            'passwords': [{
                'id': bson.ObjectId('112345678901234567890123'),
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
            }],
            'nins': [{'number': '123456781235', 'verified': True, 'primary': True}],
        }

        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'mailAliases': [{
                            'email': 'john@example.com',
                            'verified': True,
                            'primary': True
                        }],
                    },
                }
            )


class AttributeFetcherPhoneProofingTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherPhoneProofingTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            phone_plugin_init(self.am_settings),
        ]
        for userdoc in self.amdb._get_all_docs():
            proofing_user = ProofingUser(data=userdoc)
            for context in self.plugin_contexts:
                context.private_db.save(proofing_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherPhoneProofingTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'phone': [{
                            'verified': True,
                            'number': '+46700011336',
                            'primary': True
                        }],
                    },
                }
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$set': {
                        'phone': [{
                            'verified': True,
                            'number': '+46700011336',
                            'primary': True
                        }],
                    },
                }
            )


class AttributeFetcherPersonalDataTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherPersonalDataTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            personal_data_plugin_init(self.am_settings),
        ]
        #for userdoc in self.amdb._get_all_docs():
        #    personal_data_user = PersonalDataUser(data=userdoc)
        #    for context in self.plugin_contexts:
        #        context.private_db.save(personal_data_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherPersonalDataTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        for context in self.plugin_contexts:
            personal_data_user = PersonalDataUser(data=self.user_data)
            context.private_db.save(personal_data_user)

            self.assertDictEqual(
                attribute_fetcher(context, personal_data_user.user_id),
                {
                    '$set': {
                        'givenName': u'Testaren',
                        'surname': u'Testsson',
                        'displayName': u'John',
                        'preferredLanguage': u'sv',
                    },
                }
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        for context in self.plugin_contexts:
            personal_data_user = PersonalDataUser(data=self.user_data)
            context.private_db.save(personal_data_user)

            self.assertDictEqual(
                attribute_fetcher(context, personal_data_user.user_id),
                {
                    '$set': {
                        'givenName': 'Testaren',
                        'surname': 'Testsson',
                        'displayName': 'John',
                        'preferredLanguage': 'sv',
                    },
                }
            )


class AttributeFetcherSecurityTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherSecurityTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            security_plugin_init(self.am_settings),
        ]
        #for userdoc in self.amdb._get_all_docs():
        #    security_user = SecurityUser(data=userdoc)
        #    for context in self.plugin_contexts:
        #        context.private_db.save(security_user, check_sync=False)

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherSecurityTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        for context in self.plugin_contexts:
            security_user = SecurityUser(data=self.user_data)
            context.private_db.save(security_user)

            self.assertDictEqual(
                attribute_fetcher(context, security_user.user_id),
                {
                    '$set': {
                        'passwords': [{
                            'credential_id': u'112345678901234567890123',
                            'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                        }],
                        'nins': [{
                            'number': '123456781235',
                            'primary': True,
                            'verified': True
                        }],
                        'phone': [{
                            'number': '+46700011336',
                            'primary': True,
                            'verified': True
                        }]
                    },
                    '$unset': {
                        'terminated': None
                    }
                }
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_fillup_attributes(self):
        for context in self.plugin_contexts:
            security_user = SecurityUser(data=self.user_data)
            context.private_db.save(security_user)

            self.assertDictEqual(
                attribute_fetcher(context, security_user.user_id),
                {
                    '$set': {
                        'passwords': [{
                            'credential_id': u'112345678901234567890123',
                            'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                        }],
                        'nins': [{
                            'number': '123456781235',
                            'primary': True,
                            'verified': True
                        }],
                        'phone': [{
                            'number': '+46700011336',
                            'primary': True,
                            'verified': True
                        }]
                    },
                    '$unset': {
                        'terminated': None
                    }
                }
            )


class AttributeFetcherOrcidTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True
        }
        super(AttributeFetcherOrcidTests, self).setUp(init_am=True, am_settings=am_settings)
        self.user_data = deepcopy(USER_DATA)
        self.plugin_contexts = [
            orcid_plugin_init(self.am_settings),
        ]

        self.maxDiff = None

    def tearDown(self):
        for context in self.plugin_contexts:
            context.private_db._drop_whole_collection()
        super(AttributeFetcherOrcidTests, self).tearDown()

    def test_invalid_user(self):
        for context in self.plugin_contexts:
            with self.assertRaises(UserDoesNotExist):
                attribute_fetcher(context, bson.ObjectId('0' * 24))

    def test_existing_user(self):
        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
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
                                        'aud': [
                                                'APP-YIAD0N1L4B3Z3W9Q'
                                        ]
                                },
                                'expires_in': 631138518,
                                'created_by': 'orcid'
                            },
                            'given_name': 'Testaren',
                            'family_name': 'Testsson',
                            'name': None,
                            'verified': True,
                            'id': 'orcid_unique_id',
                            'created_by': 'orcid'
                        }
                    },
                }
            )

    def test_malicious_attributes(self):
        self.user_data.update({
            'malicious': 'hacker',
        })

        for context in self.plugin_contexts:
            # Write bad entry into database
            user_id = context.private_db._coll.insert(self.user_data)

            with self.assertRaises(UserHasUnknownData):
                attribute_fetcher(context, user_id)

    def test_remove_orcid(self):
        for context in self.plugin_contexts:
            proofing_user = ProofingUser(data=self.user_data)
            proofing_user.orcid = None
            context.private_db.save(proofing_user)

            self.assertDictEqual(
                attribute_fetcher(context, proofing_user.user_id),
                {
                    '$unset': {
                        'orcid': None
                    }
                }
            )
