from uuid import UUID

from eduid.userdb.ladok import Ladok, University, UniversityName

__author__ = "lundberg"


dashboard_ladok = Ladok(
    external_id=UUID("00000000-1111-2222-3333-444444444444"),
    university=University(ladok_name="DEV", name=UniversityName(sv="Testlärosäte", en="Test University")),
    is_verified=True,
    verified_by="eduid-ladok",
)
