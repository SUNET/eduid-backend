# -*- coding: utf-8 -*-


__author__ = 'lundberg'

import json
from uuid import uuid4

from eduid.scimapi.testing import ScimApiTestCase


class TestUserResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def test_get_token(self):
        response = self.client.post(url=f'/login/', data=json.dumps({'data_owner': 'eduid.se'}), headers=self.headers)
        self._assertResponse(response)

    def test_use_token(self):
        response = self.client.post(url=f'/login/', data=json.dumps({'data_owner': 'eduid.se'}), headers=self.headers)
        token = response.headers.get('Authorization')
        headers = {
            'Content-Type': 'application/scim+json',
            'Accept': 'application/scim+json',
            'Authorization': f'{token}',
        }
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1')
        response = self.client.get(url=f'/Users/{db_user.scim_id}', headers=headers)
        self._assertResponse(response)
