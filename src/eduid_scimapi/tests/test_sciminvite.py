# -*- coding: utf-8 -*-

import json
import logging
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Dict, Mapping, Optional

from bson import ObjectId

from eduid_userdb.signup import Invite as SignupInvite
from eduid_userdb.signup import InviteMailAddress, InviteType, SCIMReference

from eduid_scimapi.db.common import ScimApiProfile
from eduid_scimapi.db.invitedb import ScimApiInvite
from eduid_scimapi.schemas.invite import InviteResponse, InviteResponseSchema, NutidInviteV1
from eduid_scimapi.schemas.scimbase import Email, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema
from eduid_scimapi.schemas.user import NutidUserExtensionV1
from eduid_scimapi.testing import ScimApiTestCase

logger = logging.getLogger(__name__)


__author__ = 'lundberg'


class TestScimInvite(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.invite_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "external_id": "hubba-bubba@eduid.se",
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
            location=f'http://example.org/Invites/{db_invite.scim_id}',
            resource_type=SCIMResourceType.INVITE,
            created=db_invite.created,
            last_modified=db_invite.last_modified,
            version=db_invite.version,
        )

        signup_invite = SignupInvite(
            invite_type=InviteType.SCIM,
            invite_reference=SCIMReference(data_owner='test_data_owner', scim_id=db_invite.scim_id),
            invite_code='abc123',
            display_name=f'{db_invite.name.givenName} {db_invite.name.middleName} {db_invite.name.familyName}',
            given_name=db_invite.name.givenName,
            surname=db_invite.name.familyName,
            mail_addresses=[
                InviteMailAddress(email=db_invite.emails[0].value, primary=db_invite.emails[0].primary),
                InviteMailAddress(email=db_invite.emails[1].value, primary=db_invite.emails[1].primary),
            ],
            send_email=True,
            finish_url='https://finish.example.com',
            completed_ts=db_invite.completed,
            expires_at=datetime.fromisoformat("2020-02-25T15:52:59+00:00") + timedelta(days=180),
        )

        invite_response = InviteResponse(
            id=db_invite.scim_id,
            meta=meta,
            schemas=[SCIMSchema.NUTID_INVITE_V1, SCIMSchema.NUTID_USER_V1],
            external_id=db_invite.external_id,
            name=Name(**asdict(db_invite.name)),
            emails=[Email(**asdict(email)) for email in db_invite.emails],
            phone_numbers=[PhoneNumber(**asdict(number)) for number in db_invite.phone_numbers],
            preferred_language=db_invite.preferred_language,
            send_email=signup_invite.send_email,
            finish_url=signup_invite.finish_url,
            invite_url=f'https://signup.eduid.se/invitation/scim/{signup_invite.invite_code}',
            completed=db_invite.completed,
            expires_at=signup_invite.expires_at,
            nutid_user_v1=NutidUserExtensionV1(profiles=db_invite.profiles),
        )

        scim = InviteResponseSchema().dumps(invite_response, sort_keys=True)
        # Validation does not occur on serialization
        InviteResponseSchema().loads(scim)

        expected = {
            'schemas': [SCIMSchema.NUTID_INVITE_V1.value, SCIMSchema.NUTID_USER_V1.value],
            'emails': [
                {'primary': True, 'type': 'other', 'value': 'johnsmith@example.com'},
                {'primary': False, 'type': 'home', 'value': 'johnsmith2@example.com'},
            ],
            'externalId': 'hubba-bubba@eduid.se',
            'id': '9784e1bf-231b-4eb8-b315-52eb46dd7c4b',
            'groups': [],
            'expires_at': '2020-08-23T15:52:59+0000',
            'finishURL': 'https://finish.example.com',
            'inviteURL': 'https://signup.eduid.se/invitation/scim/abc123',
            'sendEmail': True,
            SCIMSchema.NUTID_USER_V1.value: {
                'profiles': {'student': {'attributes': {'displayName': 'Test'}, 'data': {}}}
            },
            'meta': {
                'created': '2020-02-25T15:52:59.745000',
                'lastModified': '2020-02-25T15:52:59.745000',
                'location': f'http://example.org/Invites/{db_invite.scim_id}',
                'resourceType': 'Invite',
                'version': 'W/"5e5e6829f86abf66d341d4a2"',
            },
            'name': {
                'familyName': 'Testsson',
                'formatted': 'Test T. Testsson',
                'givenName': 'Test',
                'middleName': 'Testaren',
            },
            'phoneNumbers': [
                {'primary': True, 'type': 'fax', 'value': 'tel:+461234567'},
                {'primary': False, 'type': 'home', 'value': 'tel:+5-555-555-5555'},
            ],
            'preferred_language': 'se-SV',
        }
        self.assertDictEqual(expected, json.loads(scim))


class TestInviteResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def add_invite(
        self, identifier: str, extension: Optional[Dict[str, ScimApiProfile]] = None
    ) -> Optional[ScimApiInvite]:
        invite = ScimApiInvite(scim_id=identifier,)
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
            "preferred_language": "se-SV",
        }
        assert self.invitedb
        self.invitedb.save(invite)
        return self.invitedb.get_invite_by_scim_id(scim_id=identifier)

    def _assertUpdateUpdateSuccess(self, req: Mapping, response):
        """ Function to validate successful responses to SCIM calls that update an invite according to a request. """
        if response.json.get('schemas') == [SCIMSchema.ERROR.value]:
            self.fail(f'Got SCIM error response ({response.status}):\n{response.json}')

        expected_schemas = req.get('schemas', [SCIMSchema.CORE_20_USER.value])
        if SCIMSchema.NUTID_USER_V1.value in response.json and SCIMSchema.NUTID_USER_V1.value not in expected_schemas:
            # The API can always add this extension to the response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_USER_V1.value]

        self._assertScimResponseProperties(response, resource=user, expected_schemas=expected_schemas)

        # Validate user update specifics
        self.assertEqual(user.external_id, response.json.get('externalId'))

        # If the request has NUTID profiles, ensure they are present in the response
        if SCIMSchema.NUTID_USER_V1.value in req:
            self.assertEqual(
                req[SCIMSchema.NUTID_USER_V1.value],
                response.json.get(SCIMSchema.NUTID_USER_V1.value),
                'Unexpected NUTID user data in response',
            )
        elif SCIMSchema.NUTID_USER_V1.value in response.json:
            self.fail(f'Unexpected {SCIMSchema.NUTID_USER_V1.value} in the response')

    # def test_get_users(self):
    #    for i in range(9):
    #        self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
    #    response = self.client.simulate_get(path=f'/Users', headers=self.headers)
    #    self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
    #    resources = response.json.get('Resources')
    #    self.assertEqual(self.userdb.db_count(), len(resources))

    def test_create_invite(self):

        req = {
            'schemas': [SCIMSchema.NUTID_INVITE_V1.value, SCIMSchema.NUTID_USER_V1.value],
            'name': {
                'familyName': 'Testsson',
                'formatted': 'Test T. Testsson',
                'givenName': 'Test',
                'middleName': 'Testaren',
            },
            'emails': [
                {'primary': True, 'type': 'other', 'value': 'johnsmith@example.com'},
                {'primary': False, 'type': 'home', 'value': 'johnsmith2@example.com'},
            ],
            'phoneNumbers': [
                {'primary': True, 'type': 'fax', 'value': 'tel:+461234567'},
                {'primary': False, 'type': 'home', 'value': 'tel:+5-555-555-5555'},
            ],
            'nationalIdentityNumber': '190102031234',
            'preferred_language': 'se-SV',
            'groups': ['9784e1bf-231b-4eb8-b315-52eb46dd7c4b'],
            'finishURL': 'https://finish.example.com',
            'sendEmail': True,
            SCIMSchema.NUTID_USER_V1.value: {
                'profiles': {'student': {'attributes': {'displayName': 'Test'}, 'data': {}}}
            },
        }

        response = self.client.simulate_post(path=f'/Invites/', body=self.as_json(req), headers=self.headers)
        assert response is not None
