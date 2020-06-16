# -*- coding: utf-8 -*-

from collections import OrderedDict
from datetime import datetime
from unittest import TestCase

from eduid_userdb.proofing.element import NinProofingElement, SentLetterElement
from eduid_userdb.proofing.state import LetterProofingState, OidcProofingState, ProofingState

__author__ = 'lundberg'

EPPN = 'foob-arra'

# Address as we get it from Navet
ADDRESS = OrderedDict(
    [
        (
            u'Name',
            OrderedDict([(u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'), (u'SurName', u'Testsson')]),
        ),
        (
            u'OfficialAddress',
            OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'), (u'PostalCode', u'12345'), (u'City', u'LANDET')]),
        ),
    ]
)


class ProofingStateTest(TestCase):
    def test_create_letterproofingstate(self):
        """
        {
             'eppn': 'foob-arra',
             'nin': {
                 'created_by': 'eduid-userdb.tests',
                 'created_ts': datetime(2015, 11, 9, 12, 53, 9, 708761),
                 'number': '200102034567',
                 'verification_code': 'abc123',
                 'verified': False
             },
             'proofing_letter': {
                 'is_sent': False,
                 'sent_ts': None,
                 'transaction_id': None
                 'address': {
                    'Name' : {
                        u'GivenNameMarking', u'20',
                        u'GivenName', u'Testaren Test',
                        u'SurName', u'Testsson'
                    },
                    u'OfficialAddress': {
                        u'Address2', u'\xd6RGATAN 79 LGH 10',
                        u'PostalCode', u'12345',
                        u'City', u'LANDET
                    }
                }'
             }
         }
        """
        state = LetterProofingState(
            eppn=EPPN,
            nin=NinProofingElement.from_dict(
                {
                    'number': '200102034567',
                    'created_by': 'eduid_letter_proofing',
                    'created_ts': True,
                    'verified': False,
                    'verification_code': 'abc123',
                    'verified_by': None,
                    'verified_ts': None,
                }
            ),
            id=None,
            modified_ts=None,
            proofing_letter=SentLetterElement.from_dict({}),
        )
        state.proofing_letter.address = ADDRESS
        x = state.proofing_letter.to_dict()
        state_dict = state.to_dict()
        self.assertEqual(
            sorted(state_dict.keys()), ['_id', 'eduPersonPrincipalName', 'modified_ts', 'nin', 'proofing_letter']
        )
        self.assertEqual(
            sorted(state_dict['nin'].keys()), ['created_by', 'created_ts', 'number', 'verification_code', 'verified']
        )
        self.assertEqual(
            sorted(state_dict['proofing_letter'].keys()), ['address', 'is_sent', 'sent_ts', 'transaction_id']
        )

    def test_create_oidcproofingstate(self):
        """
        {
            'eduPersonPrincipalName': 'foob-arra',
            'state': '2c84fedd-a694-46f0-b235-7c4dd7982852'
            'nonce': 'bbca50f6-5213-4784-b6e6-289bd1debda5',
            'token': 'de5b3f2a-14e9-49b8-9c78-a15fcf60d119',
        }
        """

        nin_pe = NinProofingElement.from_dict(dict(number='200102034567', application='eduid_oidc_proofing', verified=False))
        state = OidcProofingState(
            eppn=EPPN,
            state='2c84fedd-a694-46f0-b235-7c4dd7982852',
            nonce='bbca50f6-5213-4784-b6e6-289bd1debda5',
            token='de5b3f2a-14e9-49b8-9c78-a15fcf60d119',
            nin=nin_pe,
            id=None,
            modified_ts=None,
        )
        state_dict = state.to_dict()
        self.assertEqual(
            sorted(state_dict.keys()),
            ['_id', 'eduPersonPrincipalName', 'modified_ts', 'nin', 'nonce', 'state', 'token'],
        )

    def test_proofing_state_expiration(self):
        state = ProofingState(id=None, eppn=EPPN, modified_ts=datetime.now(tz=None))
        self.assertFalse(state.is_expired(1))

        expired_state = ProofingState(id=None, eppn=EPPN, modified_ts=datetime.now(tz=None))
        self.assertTrue(expired_state.is_expired(-1))
