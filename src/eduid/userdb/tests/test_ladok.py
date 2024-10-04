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

        self.assertEqual(ladok.external_id, self.external_uuid)
        self.assertEqual(ladok.created_by, "test created_by")
        self.assertIsNotNone(ladok.created_ts)

        self.assertEqual(ladok.university.ladok_name, "AB")
        self.assertEqual(ladok.university.name.sv, "Lärosätesnamn")
        self.assertEqual(ladok.university.name.en, "University Name")
        self.assertEqual(ladok.university.created_by, "test created_by")
        self.assertIsNotNone(ladok.university.created_ts)
