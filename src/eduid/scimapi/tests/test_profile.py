from unittest import TestCase

from marshmallow_dataclass import class_schema

from eduid.scimapi.schemas.scimbase import BaseSchema
from eduid.scimapi.schemas.user import NutidUserExtensionV1


class TestProfile(TestCase):
    def test_parse(self):
        displayname = 'Musse Pigg'
        data = {'profiles': {'student': {'attributes': {'displayName': displayname}}}}
        schema = class_schema(NutidUserExtensionV1, base_schema=BaseSchema)
        extension = schema().load(data)
        self.assertEqual(extension.profiles['student'].attributes['displayName'], displayname)
