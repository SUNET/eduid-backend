# -*- coding: utf-8 -*-

import json
import logging
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta

from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_userdb.signup import Invite as SignupInvite, InviteType, SCIMReference, InviteMailAddress

from eduid_scimapi.db.invitedb import ScimApiInvite
from eduid_scimapi.schemas.invite import InviteResponse, NutidExtensionV1
from eduid_scimapi.schemas.scimbase import BaseSchema, Meta, SCIMResourceType, SCIMSchema

logger = logging.getLogger(__name__)


__author__ = 'lundberg'


class TestScimUser(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.invite_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "external_id": "hubba-bubba@eduid.se",
            "version": ObjectId("5e5e6829f86abf66d341d4a2"),
            "created": datetime.fromisoformat("2020-02-25T15:52:59"),
            "last_modified": datetime.fromisoformat("2020-02-25T15:52:59"),
            "name": {
                "givenName": "Test",
                "familyName": "Testsson",
                "middleName": "Testaren",
                "formatted": "Test T. Testsson",
            },
            "emails": [
                {"value": "johnsmith@example.com", "type": "other", "primary": True},
                {"value": "johnsmith2@example.com", "type": "home", "primary": False},
            ],
        }

    def test_load_invite(self):
        invite = ScimApiInvite.from_dict(self.invite_doc1)
        # test to-dict+from-dict consistency
        invite2 = ScimApiInvite.from_dict(invite.to_dict())
        self.assertEqual(asdict(invite), asdict(invite2))

    def test_to_scimuser_doc(self):
        db_invite = ScimApiInvite.from_dict(self.invite_doc1)
        meta = Meta(
            location=f'http://example.org/Invites/{db_invite.scim_id}',
            resource_type=SCIMResourceType.invite,
            created=db_invite.created,
            last_modified=db_invite.last_modified,
            version=db_invite.version,
        )

        signup_invite = SignupInvite(
            invite_type=InviteType.SCIM,
            invite_reference=SCIMReference(data_owner='test_data_owner', scim_id=db_invite.scim_id),
            invite_code='abc123',
            display_name='Testaren Test Testsson',
            given_name='Testaren',
            surname='Testsson',
            mail_addresses=[InviteMailAddress(email='johnsmith@example.com', primary=True), InviteMailAddress(email='johnsmith2@example.com', primary=False)],
            send_email=True,
            finish_url='https://finish.example.com',
            completed=False,
            expires_at=datetime.fromisoformat("2020-02-25T15:52:59") + timedelta(days=180),
        )

        invite_response = InviteResponse(
            id=db_invite.scim_id,
            meta=meta,
            schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_INVITE_V1],
            external_id=db_invite.external_id,
            name=db_invite.name,
            emails=db_invite.emails,
            nutid_v1=NutidExtensionV1(
                send_email=signup_invite.send_email,
                finish_url=signup_invite.finish_url,
                invite_url=f"https://signup.eduid.se/invitation/scim/{signup_invite.invite_code}",
                completed=db_invite.completed,
                expires_at=signup_invite.expires_at,
            ),
        )

        schema = class_schema(InviteResponse, base_schema=BaseSchema)
        scim = schema().dumps(invite_response, sort_keys=True)

        expected = {
            "emails": [
                {"primary": True, "type": "other", "value": "johnsmith@example.com"},
                {"primary": False, "type": "home", "value": "johnsmith2@example.com"},
            ],
            "externalId": "hubba-bubba@eduid.se",
            "https://scim.eduid.se/schema/nutid/invite/v1": {
                "completed": False,
                "expires_at": "2020-08-23T15:52:59",
                "finishURL": "https://finish.example.com",
                "inviteURL": "https://signup.eduid.se/invitation/scim/abc123",
                "sendEmail": True,
            },
            "id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "meta": {
                "created": "2020-02-25T15:52:59",
                "lastModified": "2020-02-25T15:52:59",
                "location": "http://example.org/Invites/9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
                "resourceType": "Invite",
                "version": "W/\"5e5e6829f86abf66d341d4a2\"",
            },
            "name": {
                "familyName": "Testsson",
                "formatted": "Test T. Testsson",
                "givenName": "Test",
                "middleName": "Testaren",
            },
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "https://scim.eduid.se/schema/nutid/invite/v1"],
        }
        self.assertDictEqual(expected, json.loads(scim))
