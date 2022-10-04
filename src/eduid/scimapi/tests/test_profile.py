from unittest import TestCase

from eduid.scimapi.models.user import NutidUserExtensionV1


class TestProfile(TestCase):
    def test_parse(self):
        displayname = "Musse Pigg"
        data = {"profiles": {"student": {"attributes": {"displayName": displayname}}}}
        extension = NutidUserExtensionV1.parse_obj(data)
        self.assertEqual(extension.profiles["student"].attributes["displayName"], displayname)
