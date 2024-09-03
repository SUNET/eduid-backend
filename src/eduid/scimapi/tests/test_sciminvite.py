import json
import logging
import unittest
from copy import copy
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional

from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import Email, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema
from eduid.common.models.scim_invite import InviteResponse, NutidInviteExtensionV1
from eduid.common.models.scim_user import NutidUserExtensionV1, Profile
from eduid.common.utils import make_etag
from eduid.scimapi.testing import ScimApiTestCase
from eduid.scimapi.utils import filter_none
from eduid.userdb.scimapi import EventStatus, ScimApiEmail, ScimApiName, ScimApiPhoneNumber, ScimApiProfile
from eduid.userdb.scimapi.invitedb import ScimApiInvite
from eduid.userdb.signup import Invite as SignupInvite
from eduid.userdb.signup import InviteMailAddress, InvitePhoneNumber, InviteType, SCIMReference

logger = logging.getLogger(__name__)


__author__ = "lundberg"


class TestScimInvite(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.invite_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "external_id": "hubba-bubba@eduid.se",
            "name": {
                "given_name": "Test",
                "family_name": "Testsson",
                "middle_name": "Testaren",
                "formatted": "Test T. Testsson",
            },
            "emails": [
                {"value": "johnsmith@example.com", "type": "other", "primary": True},
                {"value": "johnsmith2@example.com", "type": "home", "primary": False},
            ],
            "phone_numbers": [
                {"value": "tel:+461234567", "type": "fax", "primary": True},
                {"value": "tel:+5-555-555-5555", "type": "home", "primary": False},
            ],
            "preferred_language": "se-SV",
            "version": ObjectId("5e5e6829f86abf66d341d4a2"),
            "created": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "last_modified": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "profiles": {"student": {"attributes": {"displayName": "Test"}}},
        }

    def test_load_invite(self):
        invite = ScimApiInvite.from_dict(self.invite_doc1)
        # test to-dict+from-dict consistency
        invite2 = ScimApiInvite.from_dict(invite.to_dict())
        assert invite == invite2
        assert asdict(invite) == asdict(invite2)
        assert invite.to_dict() == invite2.to_dict()

    def test_to_sciminvite_response(self):
        db_invite = ScimApiInvite.from_dict(self.invite_doc1)
        meta = Meta(
            location=f"http://example.org/Invites/{db_invite.scim_id}",
            resource_type=SCIMResourceType.INVITE,
            created=db_invite.created,
            last_modified=db_invite.last_modified,
            version=db_invite.version,
        )

        signup_invite = SignupInvite(
            invite_type=InviteType.SCIM,
            invite_reference=SCIMReference(data_owner="test_data_owner", scim_id=db_invite.scim_id),
            invite_code="abc123",
            inviter_name="Test Inviter Name",
            given_name=db_invite.name.given_name,
            surname=db_invite.name.family_name,
            mail_addresses=[
                InviteMailAddress(email=db_invite.emails[0].value, primary=db_invite.emails[0].primary),
                InviteMailAddress(email=db_invite.emails[1].value, primary=db_invite.emails[1].primary),
            ],
            send_email=True,
            finish_url="https://finish.example.com",
            completed_ts=db_invite.completed,
            expires_at=datetime.fromisoformat("2020-02-25T15:52:59+00:00") + timedelta(days=180),
        )

        invite_extension = NutidInviteExtensionV1(
            name=Name(**asdict(db_invite.name)),
            emails=[Email(**asdict(email)) for email in db_invite.emails],
            phone_numbers=[PhoneNumber(**asdict(number)) for number in db_invite.phone_numbers],
            preferred_language=db_invite.preferred_language,
            completed=db_invite.completed,
            inviter_name=signup_invite.inviter_name,
            send_email=signup_invite.send_email,
            finish_url=signup_invite.finish_url,
            invite_url=f"https://signup.eduid.se/invitation/scim/{signup_invite.invite_code}",
            expires_at=signup_invite.expires_at,
        )

        invite_response = InviteResponse(
            id=db_invite.scim_id,
            meta=meta,
            schemas=[SCIMSchema.NUTID_INVITE_CORE_V1, SCIMSchema.NUTID_INVITE_V1, SCIMSchema.NUTID_USER_V1],
            external_id=db_invite.external_id,
            nutid_invite_v1=invite_extension,
            nutid_user_v1=NutidUserExtensionV1(
                profiles={k: Profile(attributes=v.attributes, data=v.data) for k, v in db_invite.profiles.items()}
            ),
        )

        scim = invite_response.model_dump_json(exclude_none=True, by_alias=True)

        expected = {
            "schemas": [
                SCIMSchema.NUTID_INVITE_CORE_V1.value,
                SCIMSchema.NUTID_INVITE_V1.value,
                SCIMSchema.NUTID_USER_V1.value,
            ],
            "externalId": "hubba-bubba@eduid.se",
            "id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "meta": {
                "created": "2020-02-25T15:52:59.745000",
                "lastModified": "2020-02-25T15:52:59.745000",
                "location": f"http://example.org/Invites/{db_invite.scim_id}",
                "resourceType": "Invite",
                "version": 'W/"5e5e6829f86abf66d341d4a2"',
            },
            SCIMSchema.NUTID_INVITE_V1.value: {
                "emails": [
                    {"primary": True, "type": "other", "value": "johnsmith@example.com"},
                    {"primary": False, "type": "home", "value": "johnsmith2@example.com"},
                ],
                "groups": [],
                "expiresAt": "2020-08-23T15:52:59+00:00",
                "finishURL": "https://finish.example.com",
                "inviteURL": "https://signup.eduid.se/invitation/scim/abc123",
                "inviterName": "Test Inviter Name",
                "sendEmail": True,
                "name": {
                    "familyName": "Testsson",
                    "formatted": "Test T. Testsson",
                    "givenName": "Test",
                    "middleName": "Testaren",
                },
                "phoneNumbers": [
                    {"primary": True, "type": "fax", "value": "tel:+461234567"},
                    {"primary": False, "type": "home", "value": "tel:+5-555-555-5555"},
                ],
                "preferredLanguage": "se-SV",
            },
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {"student": {"attributes": {"displayName": "Test"}, "data": {}}},
                "linked_accounts": [],
            },
        }
        assert json.loads(scim) == expected


class TestInviteResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.invite_data: dict[str, Any] = {
            "invite_code": "test_invite_code",
            "name": {
                "family_name": "Testsson",
                "formatted": "Test T. Testsson",
                "given_name": "Test",
                "middle_name": "Testaren",
            },
            "emails": [
                {"primary": True, "type": "other", "value": "johnsmith@example.com"},
                {"primary": False, "type": "home", "value": "johnsmith2@example.com"},
            ],
            "phone_numbers": [
                {"primary": True, "type": "fax", "value": "tel:+461234567"},
                {"primary": False, "type": "home", "value": "tel:+5-555-555-5555"},
            ],
            "national_identity_number": "190102031234",
            "preferred_language": "se-SV",
            "groups": ["7544e1bf-231b-4eb8-b315-52eb46dd7c4b"],
            "finish_url": "https://finish.example.com",
            "inviter_name": "Test Inviter Name",
            "send_email": True,
            "profiles": {"student": {"attributes": {"displayName": "Test"}, "data": {}}},
        }

    def add_invite(self, data: Optional[dict[str, Any]] = None, update: bool = False) -> ScimApiInvite:
        invite_data = self.invite_data
        if data:
            invite_data = data
            if update:
                invite_data = copy(self.invite_data)
                invite_data.update(data)

        profiles = {}
        for profile_name, profile in invite_data.get("profiles", dict()).items():
            profiles[profile_name] = ScimApiProfile(**profile)

        db_invite = ScimApiInvite(
            name=ScimApiName(**invite_data.get("name", {})),
            emails=[ScimApiEmail.from_dict(email) for email in invite_data.get("emails", [])],
            phone_numbers=[ScimApiPhoneNumber.from_dict(number) for number in invite_data.get("phone_numbers", [])],
            nin=invite_data.get("national_identity_number"),
            preferred_language=invite_data.get("preferred_language"),
            groups=invite_data.get("groups", []),
            profiles=profiles,
        )
        assert self.invitedb
        self.invitedb.save(db_invite)

        mails_addresses = [
            InviteMailAddress(email=email["value"], primary=email["primary"]) for email in invite_data.get("emails", [])
        ]
        phone_numbers = [
            InvitePhoneNumber(number=number["value"], primary=number["primary"])
            for number in invite_data.get("phone_numbers", [])
        ]

        signup_invite = SignupInvite(
            invite_code=invite_data.get("invite_code", "invite_code not set"),
            invite_type=InviteType.SCIM,
            invite_reference=SCIMReference(data_owner=self.data_owner, scim_id=db_invite.scim_id),
            given_name=invite_data.get("name", {}).get("given_name"),
            surname=invite_data.get("name", {}).get("family_name"),
            nin=invite_data.get("national_identity_number"),
            inviter_name=invite_data.get("inviter_name", "inviter_name not set"),
            send_email=invite_data.get("send_email", False),
            mail_addresses=mails_addresses,
            phone_numbers=phone_numbers,
            finish_url=invite_data.get("finish_url"),
            expires_at=datetime.utcnow() + timedelta(seconds=self.context.config.invite_expire),
        )
        self.signup_invitedb.save(signup_invite, is_in_database=False)
        return db_invite

    def _assertUpdateSuccess(self, req: Mapping, response, invite: ScimApiInvite, signup_invite: SignupInvite):
        """Function to validate successful responses to SCIM calls that update an invite according to a request."""
        if response.json().get("schemas") == [SCIMSchema.ERROR.value]:
            self.fail(f"Got SCIM error parsed_response ({response.status}):\n{response.json}")

        expected_schemas = req.get("schemas", [SCIMSchema.NUTID_INVITE_V1.value, SCIMSchema.NUTID_USER_V1.value])

        self._assertScimResponseProperties(response, resource=invite, expected_schemas=expected_schemas)

        # Validate invite update specifics
        self.assertEqual(invite.external_id, response.json().get("externalId"))
        invite_extension = response.json().get(SCIMSchema.NUTID_INVITE_V1.value)
        self.assertIsNotNone(invite_extension)
        self._assertName(invite.name, invite_extension.get("name"))
        self.assertEqual([filter_none(email.to_dict()) for email in invite.emails], invite_extension.get("emails"))
        self.assertEqual(
            [filter_none(number.to_dict()) for number in invite.phone_numbers], invite_extension.get("phoneNumbers")
        )
        self.assertEqual(invite.nin, invite_extension.get("nationalIdentityNumber"))
        self.assertEqual(invite.preferred_language, invite_extension.get("preferredLanguage"))
        if invite.completed:
            self.assertIsNotNone(invite.external_id)
        # Validate signup invite update specifics
        self.assertEqual(signup_invite.send_email, invite_extension.get("sendEmail"))
        if signup_invite.send_email is False:
            invite_url = f"{self.context.config.invite_url}/{signup_invite.invite_code}"
            self.assertEqual(invite_url, invite_extension.get("inviteURL"))
        self.assertEqual(signup_invite.finish_url, invite_extension.get("finishURL"))
        self.assertEqual(signup_invite.inviter_name, invite_extension.get("inviterName"))

        # If the request has NUTID profiles, ensure they are present in the parsed_response
        if SCIMSchema.NUTID_USER_V1.value in req:
            self.assertEqual(
                req[SCIMSchema.NUTID_USER_V1.value],
                response.json().get(SCIMSchema.NUTID_USER_V1.value),
                "Unexpected NUTID user data in parsed_response",
            )
        elif SCIMSchema.NUTID_USER_V1.value in response.json():
            self.fail(f"Unexpected {SCIMSchema.NUTID_USER_V1.value} in the parsed_response")

    def _perform_search(
        self,
        filter: str,
        start: int = 1,
        count: int = 10,
        return_json: bool = False,
        expected_invite: Optional[ScimApiInvite] = None,
        expected_num_resources: Optional[int] = None,
        expected_total_results: Optional[int] = None,
    ):
        logger.info(f"Searching for group(s) using filter {repr(filter)}")
        req = {
            "schemas": [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            "filter": filter,
            "startIndex": start,
            "count": count,
        }
        response = self.client.post(url="/Invites/.search", json=req, headers=self.headers)
        logger.info(f"Search parsed_response:\n{response.json()}")
        if return_json:
            return response.json()
        expected_schemas = [SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value]
        response_schemas = response.json().get("schemas")
        self.assertIsInstance(response_schemas, list, "Response schemas not present, or not a list")
        self.assertEqual(
            sorted(set(expected_schemas)),
            sorted(set(response_schemas)),
            "Unexpected schema(s) in search parsed_response",
        )

        resources = response.json().get("Resources")

        if expected_invite is not None:
            expected_num_resources = 1
            expected_total_results = 1

        if expected_num_resources is not None:
            self.assertEqual(
                expected_num_resources,
                len(resources),
                f"Number of resources returned expected to be {expected_num_resources}",
            )
            if expected_total_results is None:
                expected_total_results = expected_num_resources
        if expected_total_results is not None:
            self.assertEqual(
                expected_total_results,
                response.json().get("totalResults"),
                f"Response totalResults expected to be {expected_total_results}",
            )

        if expected_invite is not None:
            self.assertEqual(
                str(expected_invite.scim_id),
                resources[0].get("id"),
                f"Search parsed_response user does not have the expected id: {str(expected_invite.scim_id)}",
            )

        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json().get("schemas"))
        resources = response.json().get("Resources")
        return resources

    # def test_get_invites(self):
    #    for i in range(9):
    #        self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
    #    parsed_response = self.client.get(url=f'/Users', headers=self.headers)
    #    self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], parsed_response.json().get('schemas'))
    #    resources = parsed_response.json().get('Resources')
    #    self.assertEqual(self.userdb.db_count(), len(resources))

    def test_create_invite(self):
        req = {
            "schemas": [
                SCIMSchema.NUTID_INVITE_CORE_V1.value,
                SCIMSchema.NUTID_INVITE_V1.value,
                SCIMSchema.NUTID_USER_V1.value,
            ],
            "externalId": "external id",
            SCIMSchema.NUTID_INVITE_V1.value: {
                "name": {
                    "familyName": "Testsson",
                    "formatted": "Test T. Testsson",
                    "givenName": "Test",
                    "middleName": "Testaren",
                },
                "emails": [
                    {"primary": True, "type": "other", "value": "johnsmith@example.com"},
                    {"primary": False, "type": "home", "value": "johnsmith2@example.com"},
                ],
                "phoneNumbers": [
                    {"primary": True, "type": "fax", "value": "tel:+461234567"},
                    {"primary": False, "type": "home", "value": "tel:+5-555-555-5555"},
                ],
                "nationalIdentityNumber": "190102031234",
                "preferredLanguage": "se-SV",
                "groups": ["7544e1bf-231b-4eb8-b315-52eb46dd7c4b"],
                "finishURL": "https://finish.example.com",
                "inviterName": "Test Inviter Name",
                "sendEmail": True,
            },
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {"student": {"attributes": {"displayName": "Test"}, "data": {}}},
                "linked_accounts": [],
            },
        }

        response = self.client.post(url="/Invites/", json=req, headers=self.headers)
        self._assertResponse(response, status_code=201)
        db_invite = self.invitedb.get_invite_by_scim_id(response.json().get("id"))
        reference = SCIMReference(data_owner=self.data_owner, scim_id=db_invite.scim_id)
        signup_invite = self.signup_invitedb.get_invite_by_reference(reference)
        self._assertUpdateSuccess(req, response, db_invite, signup_invite)
        self.assertEqual(1, self.messagedb.db_count())

        # check that the action resulted in an event in the database
        events = self.eventdb.get_events_by_resource(SCIMResourceType.INVITE, db_invite.scim_id)
        assert len(events) == 1
        event = events[0]
        assert event.resource.external_id == req["externalId"]
        assert event.data["status"] == EventStatus.CREATED.value

    def test_create_invite_missing_mandatory_attributes(self):
        req = {
            "schemas": [
                SCIMSchema.NUTID_INVITE_CORE_V1.value,
                SCIMSchema.NUTID_INVITE_V1.value,
                SCIMSchema.NUTID_USER_V1.value,
            ],
            SCIMSchema.NUTID_INVITE_V1.value: {
                "inviterName": "Test Inviter Name",
                "sendEmail": False,
            },
        }

        req1 = copy(req)
        del req1[SCIMSchema.NUTID_INVITE_V1.value]["inviterName"]
        response = self.client.post(url="/Invites/", json=req1, headers=self.headers)
        self._assertScimError(
            status=422,
            json=response.json(),
            detail=[
                {
                    "ctx": {"error": {}},
                    "loc": ["body", "https://scim.eduid.se/schema/nutid/invite/v1"],
                    "msg": "Value error, Missing inviterName",
                    "type": "value_error",
                }
            ],
            exclude_keys=["input", "url"],
        )

        req2 = copy(req)
        del req2[SCIMSchema.NUTID_INVITE_V1.value]["sendEmail"]
        response = self.client.post(url="/Invites/", json=req2, headers=self.headers)
        self._assertScimError(
            status=422,
            json=response.json(),
            detail=[
                {
                    "ctx": {"error": {}},
                    "loc": ["body", "https://scim.eduid.se/schema/nutid/invite/v1"],
                    "msg": "Value error, Missing sendEmail",
                    "type": "value_error",
                }
            ],
            exclude_keys=["input", "url"],
        )

    def test_create_invite_do_not_send_email(self):
        req = {
            "schemas": [
                SCIMSchema.NUTID_INVITE_CORE_V1.value,
                SCIMSchema.NUTID_INVITE_V1.value,
                SCIMSchema.NUTID_USER_V1.value,
            ],
            SCIMSchema.NUTID_INVITE_V1.value: {
                "name": {
                    "familyName": "Testsson",
                    "formatted": "Test T. Testsson",
                    "givenName": "Test",
                    "middleName": "Testaren",
                },
                "emails": [
                    {"primary": True, "type": "other", "value": "johnsmith@example.com"},
                    {"primary": False, "type": "home", "value": "johnsmith2@example.com"},
                ],
                "phoneNumbers": [
                    {"primary": True, "type": "fax", "value": "tel:+461234567"},
                    {"primary": False, "type": "home", "value": "tel:+5-555-555-5555"},
                ],
                "nationalIdentityNumber": "190102031234",
                "preferredLanguage": "se-SV",
                "groups": ["7544e1bf-231b-4eb8-b315-52eb46dd7c4b"],
                "finishURL": "https://finish.example.com",
                "inviterName": "Test Inviter Name",
                "sendEmail": False,
            },
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {"student": {"attributes": {"displayName": "Test"}, "data": {}}},
                "linked_accounts": [],
            },
        }

        response = self.client.post(url="/Invites/", json=req, headers=self.headers)
        self._assertResponse(response, status_code=201)
        db_invite = self.invitedb.get_invite_by_scim_id(response.json().get("id"))
        reference = SCIMReference(data_owner=self.data_owner, scim_id=db_invite.scim_id)
        signup_invite = self.signup_invitedb.get_invite_by_reference(reference)
        self._assertUpdateSuccess(req, response, db_invite, signup_invite)
        self.assertEqual(0, self.messagedb.db_count())

    def test_get_invite(self):
        db_invite = self.add_invite()
        response = self.client.get(url=f"/Invites/{db_invite.scim_id}", headers=self.headers)
        expected_schemas = [
            SCIMSchema.NUTID_INVITE_CORE_V1.value,
            SCIMSchema.NUTID_INVITE_V1.value,
            SCIMSchema.NUTID_USER_V1.value,
        ]
        self._assertScimResponseProperties(response, resource=db_invite, expected_schemas=expected_schemas)

    def test_update_invite(self):
        # TODO: For now we only support updating completed
        db_invite = self.add_invite()
        invite = self.client.get(url=f"/Invites/{db_invite.scim_id}", headers=self.headers)

        update_req = invite.json()
        update_req[SCIMSchema.NUTID_INVITE_V1.value]["completed"] = utc_now().isoformat()
        del update_req["meta"]
        self.headers["IF-MATCH"] = make_etag(db_invite.version)

        response = self.client.put(url=f"/Invites/{db_invite.scim_id}", json=update_req, headers=self.headers)
        assert response.status_code == 200

        updated_invite = self.invitedb.get_invite_by_scim_id(str(db_invite.scim_id))
        assert updated_invite.completed is not None

        expected_schemas = [
            SCIMSchema.NUTID_INVITE_CORE_V1.value,
            SCIMSchema.NUTID_INVITE_V1.value,
            SCIMSchema.NUTID_USER_V1.value,
        ]
        self._assertScimResponseProperties(response, resource=db_invite, expected_schemas=expected_schemas)

    def test_delete_invite(self):
        db_invite = self.add_invite()
        self.headers["IF-MATCH"] = make_etag(db_invite.version)
        self.client.delete(url=f"/Invites/{db_invite.scim_id}", headers=self.headers)
        reference = SCIMReference(data_owner=self.data_owner, scim_id=db_invite.scim_id)
        self.assertIsNone(self.invitedb.get_invite_by_scim_id(str(db_invite.scim_id)))
        self.assertIsNone(self.signup_invitedb.get_invite_by_reference(reference))

        # check that the action resulted in an event in the database
        events = self.eventdb.get_events_by_resource(SCIMResourceType.INVITE, db_invite.scim_id)
        assert len(events) == 1
        event = events[0]
        assert event.data["status"] == EventStatus.DELETED.value

    def test_search_user_last_modified(self):
        db_invite1 = self.add_invite()
        db_invite2 = self.add_invite(data={"invite_code": "another_invite_code"}, update=True)
        self.assertGreater(db_invite2.last_modified, db_invite1.last_modified)

        self._perform_search(
            filter=f'meta.lastModified ge "{db_invite1.last_modified.isoformat()}"',
            expected_num_resources=2,
            expected_total_results=2,
        )

        self._perform_search(
            filter=f'meta.lastModified gt "{db_invite1.last_modified.isoformat()}"', expected_invite=db_invite2
        )
