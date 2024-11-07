from collections import OrderedDict
from datetime import datetime
from unittest import TestCase

from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.userdb.proofing.element import NinProofingElement, SentLetterElement
from eduid.userdb.proofing.state import LetterProofingState, OidcProofingState, ProofingState

__author__ = "lundberg"

EPPN = "foob-arra"

# Address as we get it from Navet
ADDRESS = FullPostalAddress.model_validate(
    OrderedDict(
        [
            (
                "Name",
                OrderedDict([("GivenNameMarking", "20"), ("GivenName", "Testaren Test"), ("Surname", "Testsson")]),
            ),
            (
                "OfficialAddress",
                OrderedDict([("Address2", "\xd6RGATAN 79 LGH 10"), ("PostalCode", "12345"), ("City", "LANDET")]),
            ),
        ]
    )
)


class ProofingStateTest(TestCase):
    def _test_create_letterproofingstate(self, state: LetterProofingState, nin_expected_keys: list[str]) -> None:
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
        state.proofing_letter.address = ADDRESS
        state_dict = state.to_dict()
        _state_expected_keys = ["_id", "eduPersonPrincipalName", "nin", "modified_ts", "proofing_letter"]
        assert sorted(state_dict.keys()) == sorted(_state_expected_keys)

        self.assertEqual(
            sorted([k for k, v in state_dict["nin"].items() if v is not None]),
            sorted(nin_expected_keys),
        )
        _proofing_letter_expected_keys = ["address", "created_ts", "is_sent", "modified_ts"]
        self.assertEqual(
            sorted([k for k, v in state_dict["proofing_letter"].items() if v is not None]),
            sorted(_proofing_letter_expected_keys),
        )

    def test_create_letterproofingstate_with_ninproofingelement_from_dict(self) -> None:
        """ """
        state = LetterProofingState(
            eppn=EPPN,
            nin=NinProofingElement.from_dict(
                {
                    "number": "200102034567",
                    "created_by": "eduid_letter_proofing",
                    "verified": False,
                    "verification_code": "abc123",
                    "verified_by": None,
                    "verified_ts": None,
                }
            ),
            id=None,
            modified_ts=None,
            proofing_letter=SentLetterElement(),
        )
        # Don't expect a created_ts key here. Since the NinProofingElement is created from a dict w/o created_ts key,
        # the resulting object will get a _no_created_ts_in_db attr set to True, and its to_dict method will
        # discard the created_ts key.
        _nin_expected_keys = ["created_by", "number", "verification_code", "verified"]
        if not state.nin.no_modified_ts_in_db:
            # When _no_modified_ts_in_db is removed from Element,
            # 'modified_ts' should be added to _nin_expected_keys above
            _nin_expected_keys += ["modified_ts"]

        self._test_create_letterproofingstate(state, _nin_expected_keys)

    def test_create_letterproofingstate_with_ninproofingelement_from_dict_with_created_ts(self) -> None:
        """ """
        state = LetterProofingState(
            eppn=EPPN,
            nin=NinProofingElement.from_dict(
                {
                    "number": "200102034567",
                    "created_by": "eduid_letter_proofing",
                    "created_ts": datetime.fromisoformat("1900-01-01"),
                    "verified": False,
                    "verification_code": "abc123",
                    "verified_by": None,
                    "verified_ts": None,
                }
            ),
            id=None,
            modified_ts=None,
            proofing_letter=SentLetterElement(),
        )

        _nin_expected_keys = ["created_by", "created_ts", "number", "verification_code", "verified"]
        if not state.nin.no_modified_ts_in_db:
            # When _no_modified_ts_in_db is removed from Element,
            # 'modified_ts' should be added to _nin_expected_keys above
            _nin_expected_keys += ["modified_ts"]

        self._test_create_letterproofingstate(state, _nin_expected_keys)

    def test_create_letterproofingstate(self) -> None:
        """ """
        state = LetterProofingState(
            eppn=EPPN,
            nin=NinProofingElement(
                number="200102034567",
                created_by="eduid_letter_proofing",
                is_verified=False,
                verification_code="abc123",
                verified_by=None,
                verified_ts=None,
            ),
            id=None,
            modified_ts=None,
            proofing_letter=SentLetterElement(),
        )

        _nin_expected_keys = ["created_by", "created_ts", "number", "verification_code", "verified"]
        if not state.nin.no_modified_ts_in_db:
            # When _no_modified_ts_in_db is removed from Element,
            # 'modified_ts' should be added to _nin_expected_keys above
            _nin_expected_keys += ["modified_ts"]

        self._test_create_letterproofingstate(state, _nin_expected_keys)

    def test_create_oidcproofingstate(self) -> None:
        """
        {
            'eduPersonPrincipalName': 'foob-arra',
            'state': '2c84fedd-a694-46f0-b235-7c4dd7982852'
            'nonce': 'bbca50f6-5213-4784-b6e6-289bd1debda5',
            'token': 'de5b3f2a-14e9-49b8-9c78-a15fcf60d119',
        }
        """

        nin_pe = NinProofingElement.from_dict(
            dict(number="200102034567", application="eduid_oidc_proofing", verified=False)
        )
        state = OidcProofingState(
            eppn=EPPN,
            state="2c84fedd-a694-46f0-b235-7c4dd7982852",
            nonce="bbca50f6-5213-4784-b6e6-289bd1debda5",
            token="de5b3f2a-14e9-49b8-9c78-a15fcf60d119",
            nin=nin_pe,
            id=None,
            modified_ts=None,
        )
        state_dict = state.to_dict()
        self.assertEqual(
            sorted(state_dict.keys()),
            ["_id", "eduPersonPrincipalName", "modified_ts", "nin", "nonce", "state", "token"],
        )

    def test_proofing_state_expiration(self) -> None:
        state = ProofingState(id=None, eppn=EPPN, modified_ts=datetime.now(tz=None))
        self.assertFalse(state.is_expired(1))

        expired_state = ProofingState(id=None, eppn=EPPN, modified_ts=datetime.now(tz=None))
        self.assertTrue(expired_state.is_expired(-1))
