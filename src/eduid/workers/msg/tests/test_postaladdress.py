# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import json
from pathlib import PurePath
from unittest import TestCase

from mock import MagicMock

from eduid.workers.msg import utils


class TestPostalAddress(TestCase):
    def setUp(self):
        fn = PurePath(__file__).with_name('data') / 'navet.json'
        self.response = MagicMock()
        self.response.status_code = 200
        self.response.json.return_value = json.load(open(fn, 'r'))
        self.request = json.dumps({'identity_number': '197609272393'})
        self.navet = MagicMock()
        self.navet.personpost.navetnotification.POST = self.MockPost

    def MockPost(self, anything):
        # Mock the api call and return a mocked response
        return self.response

    def test_get_all_data_dict(self):
        response = self.navet.personpost.navetnotification.POST(self.request)
        if response.status_code == 200:
            result = response.json()
            self.assertTrue(isinstance(result, dict))

    def test_get_name(self):
        response = self.navet.personpost.navetnotification.POST(self.request)
        if response.status_code == 200:
            result = utils.navet_get_name(response.json())
            self.assertEqual(result['Name']['GivenName'], 'Saskariot Teofil')
            with self.assertRaises(KeyError):
                non_existing_address = result['OfficialAddress']

    def test_get_official_address(self):
        response = self.navet.personpost.navetnotification.POST(self.request)
        if response.status_code == 200:
            result = utils.navet_get_official_address(response.json())
            self.assertEqual(result['OfficialAddress']['Address2'], u'MALMSKILLNADSGATAN 54 25 TR LÄG 458')
            with self.assertRaises(KeyError):
                non_existing_name = result['Name']

    def test_get_name_and_official_address(self):
        response = self.navet.personpost.navetnotification.POST(self.request)
        if response.status_code == 200:
            result = utils.navet_get_name_and_official_address(response.json())
            self.assertEqual(result['Name']['GivenName'], 'Saskariot Teofil')
            self.assertEqual(result['OfficialAddress']['Address2'], u'MALMSKILLNADSGATAN 54 25 TR LÄG 458')

    def test_get_relations(self):
        response = self.navet.personpost.navetnotification.POST(self.request)
        if response.status_code == 200:
            result = utils.navet_get_relations(response.json())
            self.assertEqual(result['Relations']['Relation'][0]['RelationId']['NationalIdentityNumber'], '196910199287')
            self.assertEqual(result['Relations']['Relation'][0]['RelationType'], 'M')
