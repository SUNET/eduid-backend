from unittest import TestCase

from eduid.common.models.scim_user import NutidUserExtensionV1


class TestProfile(TestCase):
    def test_parse(self) -> None:
        displayname = "Musse Pigg"
        data = {"profiles": {"student": {"attributes": {"displayName": displayname}}}}
        extension = NutidUserExtensionV1.model_validate(data)
        self.assertEqual(extension.profiles["student"].attributes["displayName"], displayname)
