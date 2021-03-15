# -*- coding: utf-8 -*-
import json
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping

from mock import patch

from eduid.common.api.testing import EduidAPITestCase
from eduid.common.rpc.lookup_mobile_relay import LookupMobileTaskFailed
from eduid.webapp.lookup_mobile_proofing.app import MobileProofingApp, init_lookup_mobile_proofing_app
from eduid.webapp.lookup_mobile_proofing.helpers import MobileMsg

__author__ = 'lundberg'


class LookupMobileProofingTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    app: MobileProofingApp

    def setUp(self):
        self.test_user_eppn = 'hubba-baar'
        self.test_user_nin = '199001023456'
        fifteen_years_ago = datetime.now() - timedelta(days=15 * 365)
        self.test_user_nin_underage = '{}01023456'.format(fifteen_years_ago.year)
        self.mock_address = OrderedDict(
            [
                (
                    u'Name',
                    OrderedDict(
                        [(u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'), (u'Surname', u'Testsson')]
                    ),
                ),
                (
                    u'OfficialAddress',
                    OrderedDict(
                        [(u'Address2', u'\xd6RGATAN 79 LGH 10'), (u'PostalCode', u'12345'), (u'City', u'LANDET')]
                    ),
                ),
            ]
        )

        super(LookupMobileProofingTests, self).setUp(users=['hubba-baar'])

    def load_app(self, config: Mapping[str, Any]):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_lookup_mobile_proofing_app('testing', config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config.update({'environment': 'dev', 'magic_cookie': '', 'magic_cookie_name': '',},)
        return config

    def test_authenticate(self):
        response = self.browser.get('/proofing')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/proofing')
        self.assertEqual(response.status_code, 200)  # Authenticated request

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile):
        mock_find_nin_by_mobile.return_value = self.test_user_nin
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')
        self.assertEqual(response['payload']['success'], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_underage(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile):
        mock_find_nin_by_mobile.return_value = self.test_user_nin_underage
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin_underage, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')
        self.assertEqual(response['payload']['success'], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin_underage)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_no_match(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile):
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL')

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_LookupMobileTaskFailed(
        self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile
    ):
        mock_find_nin_by_mobile.side_effect = LookupMobileTaskFailed('Test Exception')
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual('POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL', response['type'])
        self.assertEqual(MobileMsg.lookup_error.value, response['payload']['message'])

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_no_match_backdoor(
        self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile
    ):
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = None
        mock_request_user_sync.side_effect = self.request_user_sync

        self.app.conf.magic_cookie = 'magic-cookie'
        self.app.conf.magic_cookie_name = 'magic-cookie'
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:

            browser.set_cookie('localhost', key='magic-cookie', value='magic-cookie')

            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')
        self.assertEqual(response['payload']['success'], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_no_match_backdoor_code_in_pro(
        self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile
    ):
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = None
        mock_request_user_sync.side_effect = self.request_user_sync

        self.app.conf.environment = 'pro'
        self.app.conf.magic_cookie = 'magic-cookie'
        self.app.conf.magic_cookie_name = 'magic-cookie'
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:

            browser.set_cookie('localhost', key='magic-cookie', value='magic-cookie')

            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL')

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_no_match_backdoor_code_unconfigured(
        self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile
    ):
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = None
        mock_request_user_sync.side_effect = self.request_user_sync

        self.app.conf.magic_cookie = ''
        self.app.conf.magic_cookie_name = 'magic-cookie'
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:

            browser.set_cookie('localhost', key='magic-cookie', value='magic-cookie')

            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL')

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_relations_to')
    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_relation(
        self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile, mock_get_relations_to
    ):
        mock_get_relations_to.return_value = ['MO']
        mock_find_nin_by_mobile.return_value = '197001021234'
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin_underage, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')
        self.assertEqual(response['payload']['success'], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin_underage)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_relations_to')
    @patch('eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_proofing_flow_relation_no_match(
        self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile, mock_get_relations_to
    ):
        mock_get_relations_to.return_value = []
        mock_find_nin_by_mobile.return_value = '197001021234'
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin_underage, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL')

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin_underage).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin_underage).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)
