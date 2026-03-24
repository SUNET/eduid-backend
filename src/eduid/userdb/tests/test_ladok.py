from unittest import TestCase
from uuid import uuid4

from eduid.userdb.ladok import Ladok, University, UniversityName

__author__ = "lundberg"


class LadokTest(TestCase):
    def setUp(self) -> None:
        self.external_uuid = uuid4()

    def test_create_ladok(self) -> None:
        university = University(
            ladok_name="AB", name=UniversityName(sv="Lärosätesnamn", en="University Name"), created_by="test created_by"
        )
        ladok = Ladok(external_id=self.external_uuid, university=university, created_by="test created_by")

        assert ladok.external_id == self.external_uuid
        assert ladok.created_by == "test created_by"
        assert ladok.created_ts is not None

        assert ladok.university.ladok_name == "AB"
        assert ladok.university.name.sv == "Lärosätesnamn"
        assert ladok.university.name.en == "University Name"
        assert ladok.university.created_by == "test created_by"
        assert ladok.university.created_ts is not None
