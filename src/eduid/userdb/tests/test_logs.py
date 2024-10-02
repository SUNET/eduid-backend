from unittest import TestCase

import pytest
from pydantic import ValidationError

from eduid.common.models.amapi_user import Reason, Source
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, DeregistrationInformation, FullPostalAddress, Name
from eduid.common.testing_base import normalised_data
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.logs.db import ProofingLog, UserChangeLog
from eduid.userdb.logs.element import (
    LadokProofing,
    LetterProofing,
    MailAddressProofing,
    NinNavetProofingLogElement,
    PhoneNumberProofing,
    ProofingLogElement,
    SeLegProofing,
    SeLegProofingFrejaEid,
    TeleAdressProofing,
    TeleAdressProofingRelation,
    UserChangeLogElement,
)
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.userdb.user import User

__author__ = "lundberg"


class TestProofingLog(TestCase):
    user: User

    def setUp(self) -> None:
        self.tmp_db = MongoTemporaryInstance.get_instance()
        self.proofing_log_db = ProofingLog(db_uri=self.tmp_db.uri)
        self.user = UserFixtures().mocked_user_standard

    def tearDown(self) -> None:
        self.proofing_log_db._drop_whole_collection()

    def test_id_proofing_data(self) -> None:
        proofing_element = ProofingLogElement(
            eppn=self.user.eppn, created_by="test", proofing_method="test", proofing_version="test"
        )
        self.proofing_log_db.save(proofing_element)

        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertEqual(hit["proofing_method"], "test")

    def test_teleadress_proofing(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "reason": "matched",
            "nin": "some_nin",
            "mobile_number": "some_mobile_number",
            "user_postal_address": {"name": {}, "official_address": {}},
            "proofing_version": "test",
        }
        proofing_element = TeleAdressProofing(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertEqual(hit["reason"], "matched")
        self.assertEqual(hit["proofing_method"], "TeleAdress")
        self.assertEqual(hit["proofing_version"], "test")

    def test_teleadress_proofing_relation(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "reason": "matched_by_navet",
            "nin": "some_nin",
            "mobile_number": "some_mobile_number",
            "user_postal_address": {"name": {}, "official_address": {}},
            "mobile_number_registered_to": "registered_national_identity_number",
            "registered_relation": ["registered_relation_to_user"],
            "registered_postal_address": {"name": {}, "official_address": {}},
            "proofing_version": "test",
        }
        proofing_element = TeleAdressProofingRelation(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertEqual(hit["reason"], "matched_by_navet")
        self.assertEqual(hit["proofing_method"], "TeleAdress")
        self.assertEqual(hit["proofing_version"], "test")

    def test_letter_proofing(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "nin": "some_nin",
            "letter_sent_to": {"name": {"some": "data"}, "address": {"some": "data"}},
            "transaction_id": "some transaction id",
            "user_postal_address": {"name": {}, "official_address": {}},
            "proofing_version": "test",
        }
        proofing_element = LetterProofing(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertIsNotNone(hit["letter_sent_to"])
        self.assertIsNotNone(hit["transaction_id"])
        self.assertEqual(hit["proofing_method"], "letter")
        self.assertEqual(hit["proofing_version"], "test")

    def test_mail_address_proofing(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "mail_address": "some_mail_address",
            "proofing_version": "test",
            "reference": "reference id",
        }
        proofing_element = MailAddressProofing(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertEqual(hit["proofing_method"], "e-mail")
        self.assertEqual(hit["mail_address"], "some_mail_address")

    def test_phone_number_proofing(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "phone_number": "some_phone_number",
            "proofing_version": "test",
            "reference": "reference id",
        }
        proofing_element = PhoneNumberProofing(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertEqual(hit["proofing_method"], "sms")
        self.assertEqual(hit["phone_number"], "some_phone_number")
        self.assertEqual(hit["proofing_version"], "test")

    def test_se_leg_proofing(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "proofing_version": "test",
            "nin": "national_identity_number",
            "vetting_by": "provider",
            "transaction_id": "transaction_id",
            "user_postal_address": {"name": {}, "official_address": {}},
        }
        proofing_element = SeLegProofing(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertIsNotNone(hit["nin"])
        self.assertIsNotNone(hit["user_postal_address"])
        self.assertEqual(hit["vetting_by"], "provider")
        self.assertEqual(hit["transaction_id"], "transaction_id")
        self.assertEqual(hit["proofing_method"], "se-leg")
        self.assertEqual(hit["proofing_version"], "test")

    def test_se_leg_proofing_freja(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "proofing_version": "test",
            "nin": "national_identity_number",
            "transaction_id": "transaction_id",
            "opaque_data": "some data",
            "user_postal_address": {"name": {}, "official_address": {}},
        }
        proofing_element = SeLegProofingFrejaEid(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertIsNotNone(hit["nin"])
        self.assertIsNotNone(hit["user_postal_address"])
        self.assertEqual(hit["vetting_by"], "Freja eID")
        self.assertEqual(hit["transaction_id"], "transaction_id")
        self.assertEqual(hit["opaque_data"], "some data")
        self.assertEqual(hit["proofing_method"], "se-leg")
        self.assertEqual(hit["proofing_version"], "test")

    def test_ladok_proofing(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "nin": "190102031234",
            "external_id": "acf31a30-991a-438b-96ec-a5a4f57bb8c9",
            "ladok_name": "AB",
            "proofing_version": "test",
        }
        proofing_element = LadokProofing(**data)
        for key, value in data.items():
            if key == "eppn":
                continue
            self.assertIn(key, proofing_element.to_dict())
            self.assertEqual(value, proofing_element.to_dict().get(key))

        self.proofing_log_db.save(proofing_element)
        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        self.assertEqual(hit["eduPersonPrincipalName"], self.user.eppn)
        self.assertEqual(hit["created_by"], "test")
        self.assertIsNotNone(hit["created_ts"])
        self.assertEqual(hit["proofing_method"], "eduid_ladok")
        self.assertEqual(hit["nin"], "190102031234")
        self.assertEqual(hit["external_id"], "acf31a30-991a-438b-96ec-a5a4f57bb8c9")
        self.assertEqual(hit["ladok_name"], "AB")
        self.assertEqual(hit["proofing_version"], "test")

    def test_blank_string_proofing_data(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "phone_number": "some_phone_number",
            "proofing_version": "test",
            "reference": "reference id",
        }
        proofing_element = PhoneNumberProofing(**data)
        with pytest.raises(ValidationError) as exc_info:
            proofing_element.phone_number = ""

        assert normalised_data(exc_info.value.errors(), exclude_keys=["url"]) == [
            {
                "ctx": {"min_length": 1},
                "input": "",
                "loc": ["phone_number"],
                "msg": "String should have at least 1 character",
                "type": "string_too_short",
            }
        ], f"Wrong error message: {normalised_data(exc_info.value.errors(), exclude_keys=['url'])}"

    def test_boolean_false_proofing_data(self) -> None:
        data = {
            "eppn": self.user.eppn,
            "created_by": "test",
            "proofing_version": "test",
            "reference": "reference id",
        }
        proofing_element = PhoneNumberProofing.model_construct(**data, phone_number=0)  # type: ignore[arg-type]
        self.assertTrue(self.proofing_log_db.save(proofing_element))

        proofing_element = PhoneNumberProofing.model_construct(**data, phone_number=False)  # type: ignore[arg-type]
        self.assertTrue(self.proofing_log_db.save(proofing_element))

    def test_deregistered_proofing_data(self) -> None:
        proofing_element = NinNavetProofingLogElement(
            eppn=self.user.eppn,
            created_by="test",
            proofing_method="test",
            proofing_version="test",
            nin="190102031234",
            user_postal_address=FullPostalAddress(name=Name(given_name="Test", surname="Testsson")),
            deregistration_information=DeregistrationInformation(
                date="20220505", cause_code=DeregisteredCauseCode.EMIGRATED
            ),
        )
        self.proofing_log_db.save(proofing_element)

        result = list(self.proofing_log_db._coll.find({}))
        self.assertEqual(len(result), 1)
        hit = result[0]
        assert hit["deregistration_information"] == {"cause_code": "UV", "date": "20220505"}
        assert hit["user_postal_address"] == {
            "name": {"given_name": "Test", "surname": "Testsson"},
            "official_address": {},
        }


class TestUserChangeLog(TestCase):
    def setUp(self) -> None:
        self.tmp_db = MongoTemporaryInstance.get_instance()
        self.user_log_db = UserChangeLog(db_uri=self.tmp_db.uri)

    def tearDown(self) -> None:
        self.user_log_db._drop_whole_collection()

    def _insert_log_fixtures(self):
        data_1 = UserChangeLogElement(
            eppn="hubba-bubba",
            created_by="test",
            diff="diff",
            reason=Reason.TEST,
            source=Source.TEST,
        )

        data_2 = UserChangeLogElement(
            eppn="hubba-bubba",
            created_by="test",
            diff="diff",
            reason=Reason.TEST,
            source=Source.TEST,
        )

        self.user_log_db.save(data_1)
        self.user_log_db.save(data_2)

        res = list(self.user_log_db._coll.find({}))
        assert len(res) == 2
        assert res[0]["eduPersonPrincipalName"] == "hubba-bubba"
        assert res[1]["eduPersonPrincipalName"] == "hubba-bubba"

    def test_get_by_eppn(self) -> None:
        self._insert_log_fixtures()

        res_1 = self.user_log_db.get_by_eppn("hubba-bubba")
        assert len(res_1) == 2
        assert res_1[0].eppn == "hubba-bubba"
        assert res_1[1].eppn == "hubba-bubba"

        data_3 = UserChangeLogElement(
            eppn="hubba-biss",
            created_by="test",
            diff="diff",
            reason=Reason.TEST,
            source=Source.TEST,
        )

        self.user_log_db.save(data_3)

        res_2 = self.user_log_db.get_by_eppn("hubba-biss")
        assert len(res_2) == 1
