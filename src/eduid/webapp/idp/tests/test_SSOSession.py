from datetime import UTC, datetime

from bson import ObjectId

from eduid.userdb.element import ElementKey
from eduid.userdb.testing import SetupConfig
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tests.test_api import IdPAPITests


class test_SSOSession(IdPAPITests):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        self.data = {
            "_id": ObjectId("5fcde44d56cf512b51f1ac4e"),
            "session_id": "ZjYzOTcwNWItYzUyOS00M2U1LWIxODQtODMxYTJhZjQ0YzA1",
            "eppn": self.test_user.eppn,
            "authn_request_id": "id-IgHyGTmxBEORfx5NJ",
            "authn_credentials": [
                {
                    "cred_id": "5fc8b78cbdaa0bf337490db1",
                    "external": None,
                    "fido": None,
                    "timestamp": datetime.fromisoformat("2020-09-13T12:26:40+00:00"),
                }
            ],
            "authn_timestamp": datetime.fromisoformat("2020-09-13T12:26:40+00:00"),
            "created_ts": datetime.fromisoformat("2020-12-07T08:14:05.744+00:00"),
            "expires_at": datetime.fromisoformat("2020-12-08T00:00:00+00:00"),
        }

    def test_from_dict(self) -> None:
        session = SSOSession.from_dict(self.data)
        assert session.authn_timestamp == datetime.fromisoformat("2020-09-13T12:26:40+00:00")
        assert session.authn_credentials[0].cred_id == "5fc8b78cbdaa0bf337490db1"
        assert session.authn_credentials[0].timestamp == datetime.fromisoformat("2020-09-13T12:26:40+00:00")

    def test_str_method(self) -> None:
        session = SSOSession.from_dict(self.data)
        assert len(str(session)) > 40

    def test_with_datetime_authn_timestamp(self) -> None:
        int_session = SSOSession.from_dict(self.data)
        data = dict(self.data)
        # Change authn_timestamp to datetime format.
        data["authn_timestamp"] = datetime.fromisoformat("2020-09-13T12:26:40+00:00")
        datetime_session = SSOSession.from_dict(data)
        assert int_session.authn_timestamp == datetime_session.authn_timestamp
        assert isinstance(datetime_session.authn_timestamp, datetime)

    def test_to_dict_from_dict(self) -> None:
        session1 = SSOSession.from_dict(self.data)
        session2 = SSOSession.from_dict(session1.to_dict())
        assert session1.to_dict() == session2.to_dict()
        assert session2.to_dict() == self.data

    def test_only_store_newest_credential_use(self) -> None:
        pw = AuthnData(cred_id=ElementKey("password"), timestamp=datetime.fromtimestamp(10, tz=UTC))
        older = AuthnData(cred_id=ElementKey("token"), timestamp=datetime.fromtimestamp(20, tz=UTC))
        newer = AuthnData(cred_id=ElementKey("token"), timestamp=datetime.fromtimestamp(30, tz=UTC))

        _data = dict(self.data)
        _data["authn_credentials"] = []
        session1 = SSOSession.from_dict(_data)
        session1.add_authn_credential(pw)
        session1.add_authn_credential(older)
        session1.add_authn_credential(newer)

        assert session1.authn_credentials == [pw, newer]

        session2 = SSOSession.from_dict(_data)
        session2.add_authn_credential(pw)
        session2.add_authn_credential(newer)
        session2.add_authn_credential(older)

        assert session2.authn_credentials == [pw, newer]
