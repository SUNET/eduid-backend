from datetime import datetime

from bson import ObjectId

from eduid_webapp.idp.sso_session import SSOSession
from eduid_webapp.idp.tests.test_app import IdPTests


class test_SSOSession(IdPTests):
    def setUp(self):
        super().setUp()
        # This is real data extracted from MongoDB before a lot of refactoring
        self.data = {
            '_id': ObjectId('5fcde44d56cf512b51f1ac4e'),
            'session_id': b'ZjYzOTcwNWItYzUyOS00M2U1LWIxODQtODMxYTJhZjQ0YzA1',
            'username': self.test_user.eppn,
            'data': {
                'user_id': self.test_user.user_id,
                'authn_request_id': 'id-IgHyGTmxBEORfx5NJ',
                'authn_credentials': [
                    {
                        'cred_id': '5fc8b78cbdaa0bf337490db1',
                        'authn_ts': datetime.fromisoformat('2020-09-13T12:26:40+00:00'),
                    }
                ],
                'authn_timestamp': 1600000000,
                'external_mfa': None,
            },
            'created_ts': datetime.fromisoformat('2020-12-07T08:14:05.744+00:00'),
        }

    def test_from_dict(self):
        session = SSOSession.from_dict(self.data, self.app.userdb)
        assert session.authn_timestamp == datetime.fromisoformat('2020-09-13T12:26:40+00:00')
        assert session.authn_credentials[0].cred_id == "5fc8b78cbdaa0bf337490db1"
        assert session.authn_credentials[0].timestamp == datetime.fromisoformat('2020-09-13T12:26:40+00:00')

    def test_str_method(self):
        session = SSOSession.from_dict(self.data, self.app.userdb)
        assert str(session) == '<SSOSession: uid=012345678901234567890123, ts=2020-09-13T12:26:40+00:00>'

    def test_with_datetime_authn_timestamp(self):
        int_session = SSOSession.from_dict(self.data, self.app.userdb)
        data = dict(self.data)
        # Change authn_timestamp to datetime format.
        data['authn_timestamp'] = datetime.fromisoformat('2020-09-13T12:26:40+00:00')
        datetime_session = SSOSession.from_dict(data, self.app.userdb)
        assert int_session.authn_timestamp == datetime_session.authn_timestamp
        assert isinstance(datetime_session.authn_timestamp, datetime)

    def test_to_dict_from_dict(self):
        session1 = SSOSession.from_dict(self.data, self.app.userdb)
        session2 = SSOSession.from_dict(session1.to_dict(), self.app.userdb)
        assert session1.to_dict() == session2.to_dict()
        assert session2.to_dict() == self.data
