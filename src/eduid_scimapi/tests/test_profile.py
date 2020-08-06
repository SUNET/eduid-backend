from unittest import TestCase

from marshmallow_dataclass import class_schema

from eduid_scimapi.schemas.user import NutidExtensionV1


class TestProfile(TestCase):
    def test_parse(self):
        displayname = 'Musse Pigg'
        data = {'profiles': {'student': {'attributes': {'displayName': displayname}}}}
        schema = class_schema(NutidExtensionV1)
        extension = schema().load(data)
        self.assertEqual(extension.profiles['student'].attributes['displayName'], displayname)
