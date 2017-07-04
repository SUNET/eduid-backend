# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from copy import deepcopy
from collections import OrderedDict
from datetime import datetime, timedelta
from mock import patch

from eduid_userdb.data_samples import NEW_USER_EXAMPLE
from eduid_userdb.user import User
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.lookup_mobile_proofing.app import init_lookup_mobile_proofing_app

__author__ = 'lundberg'


class LookupMobileProofingTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_user_nin = '199001023456'
        fifteen_years_ago = datetime.now() - timedelta(days=15*365)
        self.test_user_nin_underage = '{}01023456'.format(fifteen_years_ago.year)
        self.mock_address = OrderedDict([
            (u'Name', OrderedDict([
                (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                (u'Surname', u'Testsson')])),
            (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                              (u'PostalCode', u'12345'),
                                              (u'City', u'LANDET')]))
        ])

        super(LookupMobileProofingTests, self).setUp()

        # Replace user with one without previous proofings
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['nins']
        user = User(data=userdata)
        user.modified_ts = True
        self.app.central_userdb.save(user, check_sync=False)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_lookup_mobile_proofing_app('testing', config)

    def update_config(self, config):
        config.update({
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'LOOKUP_MOBILE_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
        })
        return config

    def tearDown(self):
        super(LookupMobileProofingTests, self).tearDown()
        with self.app.app_context():
            self.app.proofing_userdb._drop_whole_collection()
            self.app.proofing_log._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    def test_authenticate(self):
        response = self.browser.get('/proofing')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/proofing')
        self.assertEqual(response.status_code, 200)  # Authenticated request

    @patch('eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_proofing_flow(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile):
        mock_find_nin_by_mobile.return_value = self.test_user_nin
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True

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

        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_proofing_flow_underage(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile):
        mock_find_nin_by_mobile.return_value = self.test_user_nin_underage
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True

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

        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin_underage)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_proofing_flow_no_match(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile):
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')
        self.assertEqual(response['payload']['success'], False)

        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.msg.MsgRelay.get_relations_to')
    @patch('eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_proofing_flow_relation(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile, mock_get_relations_to):
        mock_get_relations_to.return_value = ['MO']
        mock_find_nin_by_mobile.return_value = '197001021234'
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True

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

        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin_underage)
        self.assertEqual(user.nins.primary.created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.verified_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.msg.MsgRelay.get_relations_to')
    @patch('eduid_webapp.lookup_mobile_proofing.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_proofing_flow_relation_no_match(self, mock_request_user_sync, mock_get_postal_address, mock_find_nin_by_mobile, mock_get_relations_to):
        mock_get_relations_to.return_value = []
        mock_find_nin_by_mobile.return_value = '197001021234'
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin_underage, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS')
        self.assertEqual(response['payload']['success'], False)

        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.find(self.test_user_nin_underage).created_by, 'lookup_mobile_proofing')
        self.assertEqual(user.nins.find(self.test_user_nin_underage).is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)
