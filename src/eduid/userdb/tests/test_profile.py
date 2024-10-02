from unittest import TestCase

import pytest
from pydantic import ValidationError

from eduid.common.testing_base import normalised_data
from eduid.userdb.profile import Profile, ProfileList

__author__ = "lundberg"


OPAQUE_DATA = {"a_string": "I am a string", "an_int": 3, "a_list": ["eins", 2, "drei"], "a_map": {"some": "data"}}


class ProfileTest(TestCase):
    def test_create_profile(self) -> None:
        profile = Profile(
            owner="test owner",
            profile_schema="test schema",
            profile_data=OPAQUE_DATA,
            created_by="test created_by",
        )
        self.assertEqual(profile.owner, "test owner")
        self.assertEqual(profile.profile_schema, "test schema")
        self.assertEqual(profile.created_by, "test created_by")
        self.assertIsNotNone(profile.created_ts)
        for key, value in OPAQUE_DATA.items():
            self.assertIn(key, profile.profile_data)
            self.assertEqual(value, profile.profile_data[key])

    def test_profile_list(self) -> None:
        profile = Profile(
            owner="test owner 1",
            profile_schema="test schema",
            profile_data=OPAQUE_DATA,
            created_by="test created_by",
        )
        profile2 = Profile(
            owner="test owner 2",
            created_by="test created_by",
            profile_schema="test schema",
            profile_data=OPAQUE_DATA,
        )

        profile_list = ProfileList(elements=[profile, profile2])
        self.assertIsNotNone(profile_list)
        self.assertEqual(profile_list.count, 2)
        self.assertIsNotNone(profile_list.find("test owner 1"))
        self.assertIsNotNone(profile_list.find("test owner 2"))

    def test_empty_profile_list(self) -> None:
        profile_list = ProfileList()
        self.assertIsNotNone(profile_list)
        self.assertEqual(profile_list.count, 0)

    def test_profile_list_owner_conflict(self) -> None:
        profile = Profile(
            owner="test owner 1",
            profile_schema="test schema",
            profile_data=OPAQUE_DATA,
            created_by="test created_by",
        )
        profile_dict = profile.to_dict()
        profile2 = Profile.from_dict(profile_dict)

        with pytest.raises(ValidationError) as exc_info:
            ProfileList(elements=[profile, profile2])

        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("Duplicate element key: 'test owner 1'")},
                    "loc": ("elements",),
                    "msg": "Value error, Duplicate element key: 'test owner 1'",
                    "type": "value_error",
                }
            ]
        )
