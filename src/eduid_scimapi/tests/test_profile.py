from unittest import TestCase

from eduid_scimapi.profile import parse_nutid_profiles


class TestProfile(TestCase):
    def test_parse(self):
        displayname = 'Musse Pigg'
        data = {'profiles': {'student': {'attributes': {'displayName': displayname}}}}
        profiles = parse_nutid_profiles(data)
        self.assertEqual(profiles['student'].attributes['displayName'], displayname)
