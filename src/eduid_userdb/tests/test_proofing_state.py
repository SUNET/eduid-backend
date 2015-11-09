# -*- coding: utf-8 -*-

from unittest import TestCase

from collections import OrderedDict
from eduid_userdb.proofing.proofing_state import LetterProofingState

__author__ = 'lundberg'

USERID = '123467890123456789014567'

# Address as we get it from Navet
ADDRESS = OrderedDict([
    (u'Name', OrderedDict([
        (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
        (u'SurName', u'Testsson')])),
    (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                      (u'PostalCode', u'12345'),
                                      (u'City', u'LANDET')]))
])


class ProofingStateTest(TestCase):

    def test_create_letterproofingstate(self):
        """
        {
             'user_id': ObjectId(USERID),
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
        state = LetterProofingState({
            'user_id': USERID,
            'nin': {
                'number': '200102034567',
                'created_by': 'eduid-userdb.tests',
                'created_ts': True,
                'verified': False,
                'verification_code': 'abc123'
            }
        })
        state.proofing_letter.address = ADDRESS
        state_dict = state.to_dict()
        self.assertItemsEqual(state_dict.keys(), ['_id', 'user_id', 'nin', 'proofing_letter'])
        self.assertItemsEqual(state_dict['nin'].keys(), ['created_by', 'created_ts', 'number', 'verification_code',
                                                         'verified'])
        self.assertItemsEqual(state_dict['proofing_letter'].keys(), ['is_sent', 'sent_ts', 'transaction_id',
                                                                     'address'])



