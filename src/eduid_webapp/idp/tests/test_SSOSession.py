import unittest
from datetime import datetime

from bson import ObjectId

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.testing import MongoTestCase

from eduid_webapp.idp.sso_session import SSOSession
from eduid_webapp.idp.tests.test_app import IdPTests


class test_SSOSession(IdPTests):
    def test_from_dict(self):
        data = {
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
        session = SSOSession.from_dict(data['data'], self.app.userdb)
        assert session.authn_timestamp == datetime.fromisoformat('2020-09-13T12:26:40+00:00').timestamp()
        assert session.authn_credentials[0].cred_id == "5fc8b78cbdaa0bf337490db1"
        assert session.authn_credentials[0].timestamp == datetime.fromisoformat('2020-09-13T12:26:40+00:00')
