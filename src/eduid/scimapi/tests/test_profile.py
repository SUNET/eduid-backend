from eduid.common.models.scim_user import NutidUserExtensionV1


class TestProfile:
    def test_parse(self) -> None:
        displayname = "Musse Pigg"
        data = {"profiles": {"student": {"attributes": {"displayName": displayname}}}}
        extension = NutidUserExtensionV1.model_validate(data)
        assert extension.profiles["student"].attributes["displayName"] == displayname
