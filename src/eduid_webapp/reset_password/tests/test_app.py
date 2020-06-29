# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the SUNET nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from __future__ import absolute_import

import json
import time
from typing import Any, Optional
from urllib.parse import quote_plus

from flask import url_for
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.testing import TestVCCSClient
from eduid_common.authn.tests.test_fido_tokens import SAMPLE_WEBAUTHN_REQUEST
from eduid_userdb.credentials import Webauthn
from eduid_userdb.exceptions import DocumentDoesNotExist, UserDoesNotExist, UserHasNotCompletedSignup
from eduid_userdb.fixtures.fido_credentials import webauthn_credential as sample_credential

from eduid_webapp.reset_password.app import init_reset_password_app
from eduid_webapp.reset_password.helpers import (
    ResetPwMsg,
    generate_suggested_password,
    get_extra_security_alternatives,
    get_zxcvbn_terms,
    hash_password,
    send_verify_phone_code,
)
from eduid_webapp.reset_password.settings.common import ResetPasswordConfig

__author__ = 'eperez'


class ResetPasswordTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_user_email = 'johnsmith@example.com'
        super(ResetPasswordTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_reset_password_app('testing', config)

    def update_config(self, config):
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},
                'vccs_url': 'http://vccs',
                'email_code_timeout': 7200,
                'phone_code_timeout': 600,
                'password_entropy': 25,
                'no_authn_urls': [r'/reset.*'],
                'u2f_app_id': 'https://eduid.se/u2f-app-id.json',
                'fido2_rp_id': 'idp.dev.eduid.se',
                'u2f_valid_facets': ['https://dashboard.dev.eduid.se', 'https://idp.dev.eduid.se'],
            }
        )
        return ResetPasswordConfig(**config)

    def tearDown(self):
        super(ResetPasswordTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    # Parameterized test methods

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _post_email_address(
        self,
        mock_sendmail: Any,
        data1: Optional[dict] = None,
        sendmail_return: bool = True,
        sendmail_side_effect: Any = None,
    ):
        """
        POST an email address to start the reset password process for the corresponding account.

        :param data1: to control the data sent with the POST request.
        :param sendmail_return: mock return value for the sendmail function
        :param sendmail_side_effect: Mock raising exception calling the sendmail function
        """
        mock_sendmail.return_value = sendmail_return
        mock_sendmail.side_effect = sendmail_side_effect
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                    return c.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _post_reset_code(self, mock_sendmail: Any, data1: Optional[dict] = None, data2: Optional[dict] = None):
        """
        Create a password rest state for the test user, grab the created verification code from the db,
        and use it to get configuration for the reset form.

        :param data1: to control the data (email) sent to create the reset state
        :param data2: to control the data (verification code) used to get the configuration.
        """
        mock_sendmail.return_value = True
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)
                    response = c.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

                    url = url_for('reset_password.config_reset_pw', _external=True)
                    data = {
                        'code': state.email_code.code,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data2 is not None:
                        data.update(data2)
                    return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _post_reset_password(
        self,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_get_vccs_client: Any,
        data1: Optional[dict] = None,
        data2: Optional[dict] = None,
    ):
        """
        Test sending data from the reset password form, without extra security.
        First POST an email address to the /reset endpoint to create a reset password state,
        and then POST data to the endpoint to actually reset the password.

        :param data1: control the data sent to the /reset endpoint (an email address)
        :param data2: control the data sent to actually reset the password.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)
                    response = c.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

                    # check that the user has verified data
                    user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                    verified_phone_numbers = user.phone_numbers.verified.to_list()
                    self.assertEqual(len(verified_phone_numbers), 1)
                    verified_nins = user.nins.verified.to_list()
                    self.assertEqual(len(verified_nins), 2)

                    new_password = generate_suggested_password()
                    session.reset_password.generated_password_hash = hash_password(new_password)
                    session.persist()
                    url = url_for('reset_password.set_new_pw', _external=True)
                    data = {
                        'csrf_token': session.get_csrf_token(),
                        'code': state.email_code.code,
                        'password': new_password,
                    }
                    if data2 == {}:
                        data = {}
                    elif data2 is not None:
                        data.update(data2)

                    return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def _post_choose_extra_sec(
        self,
        mock_sendsms: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_get_vccs_client: Any,
        sendsms_side_effect: Any = None,
        data1: Optional[dict] = None,
        data2: Optional[dict] = None,
        data3: Optional[dict] = None,
        repeat: bool = False,
    ):
        """
        Test choosing extra security via a confirmed phone number to reset the password.
        First create the reset password state in the database, then POST the generated code
        to get the configuration for the reset password form, and finally POST the code and
        an index selecting the phone number to use for extra security.

        :param data1: to control what email is sent to create the state and start the process
        :param data2: to control the code sent to obtain configuration for the reset form
        :param data3: to control what data is sent (what confirmed pone number is chosen) to send
                      an SMS with an extra security verification code.
        :param repeat: if True, try to trigger sending the SMS twice.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        if sendsms_side_effect:
            mock_sendsms.side_effect = sendsms_side_effect

        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)
                    response = c.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

                    url = url_for('reset_password.config_reset_pw', _external=True)
                    data = {
                        'code': state.email_code.code,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data2 is not None:
                        data.update(data2)
                    response = c.post(url, data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)

                    url = url_for('reset_password.choose_extra_security_phone', _external=True)
                    data = {'csrf_token': session.get_csrf_token(), 'code': state.email_code.code, 'phone_index': '0'}
                    if data3 is not None:
                        data.update(data3)

                    response = c.post(url, data=json.dumps(data), content_type=self.content_type_json)
                    if repeat:
                        response = c.post(url, data=json.dumps(data), content_type=self.content_type_json)
                    return response

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def _post_reset_password_secure_phone(
        self,
        mock_sendsms: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_get_vccs_client: Any,
        data1: Optional[dict] = None,
        data2: Optional[dict] = None,
    ):
        """
        Test fully resetting the password with extra security via a verification code sent by SMS.
        First initialize the reset password state by POSTing an email to the initial endpoint,
        then retrieve the state form the db and modify it in the way that choosing extra security
        with a verified phone number would, and finally POST the verification codes and
        the new password to finally reset the password.

        :param data1: To control the email sent to initiate the process
        :param data2: To control the data sent to actually finally reset the password.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)
                    response = c.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)

                    user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                    alternatives = get_extra_security_alternatives(user, 'dummy.session.prefix')
                    state.extra_security = alternatives
                    state.email_code.is_verified = True
                    self.app.password_reset_state_db.save(state)
                    phone_number = state.extra_security['phone_numbers'][0]
                    send_verify_phone_code(state, phone_number['number'])

                    new_password = generate_suggested_password()
                    session.reset_password.generated_password_hash = hash_password(new_password)
                    url = url_for('reset_password.set_new_pw_extra_security_phone', _external=True)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                    data = {
                        'csrf_token': session.get_csrf_token(),
                        'code': state.email_code.code,
                        'phone_code': state.phone_code.code,
                        'password': new_password,
                    }
                    if data2 is not None:
                        data.update(data2)

            return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('fido2.cose.ES256.verify')
    def _post_reset_password_secure_token(
        self,
        mock_verify: Any,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        mock_sendmail: Any,
        data1: Optional[dict] = None,
        credential_data: Optional[dict] = None,
        data2: Optional[dict] = None,
        fido2state: Optional[dict] = None,
        custom_password: Optional[str] = None,
    ):
        """
        Test resetting the password with extra security via a fido token.
        First create the reset password state in the database, then add a webauthn
        credential to the test user, then get the state from the db and modify it
        as if the user had chosen extra security via the webauthn token,
        and finally send the necessary data to actually reset the password.

        :param data1: to control what email is sent to create the state and start the process
        :param credential_data: to control the data set as webauthn credential on the test user
        :param data2: to control the data POSTed to finally reset the password
        :param fido2state: to control the fido state kept in the session
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendmail.return_value = True
        mock_verify.return_value = True
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'csrf_token': session.get_csrf_token(),
                        'email': self.test_user_email,
                    }
                    if data1 is not None:
                        data.update(data1)
                    response = c.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)

                    credential = sample_credential.to_dict()
                    if credential_data:
                        credential.update(credential_data)
                    webauthn_credential = Webauthn.from_dict(credential)
                    user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                    user.credentials.add(webauthn_credential)
                    self.app.central_userdb.save(user, check_sync=False)

                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                    alternatives = get_extra_security_alternatives(user, 'dummy.session.prefix')
                    state.extra_security = alternatives
                    state.email_code.is_verified = True
                    self.app.password_reset_state_db.save(state)

                    if fido2state is None:
                        fido2state = {
                            'challenge': '3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc',
                            'user_verification': 'preferred',
                        }
                    session['eduid_webapp.reset_password.views.webauthn.state'] = json.dumps(fido2state)
                    new_password = generate_suggested_password()
                    session.reset_password.generated_password_hash = hash_password(new_password)
                    session.persist()
                    url = url_for('reset_password.set_new_pw_extra_security_token', _external=True)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                    data = {
                        'csrf_token': session.get_csrf_token(),
                        'code': state.email_code.code,
                        'password': custom_password or new_password,
                    }
                    data.update(SAMPLE_WEBAUTHN_REQUEST)
                    if data2 == {}:
                        data = {}
                    elif data2 is not None:
                        data.update(data2)

            return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _get_email_code_backdoor(self, mock_sendmail: Any, data1: Optional[dict] = None):
        """
        Create a password rest state for the test user, grab the created verification code from the db,
        and use it to get configuration for the reset form.

        :param data1: to control the data (email) sent to create the reset state
        """
        mock_sendmail.return_value = True
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)
                    response = client.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)

                    client.set_cookie(
                        'localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie
                    )

                    eppn = quote_plus(self.test_user_eppn)

                    return client.get(f'/reset/get-email-code?eppn={eppn}')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def _get_phone_code_backdoor(
        self,
        mock_sendsms: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_get_vccs_client: Any,
        sendsms_side_effect: Any = None,
    ):
        """
        Test choosing extra security via a confirmed phone number to reset the password,
        and getting the generated phone verification code through the backdoor
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        if sendsms_side_effect:
            mock_sendsms.side_effect = sendsms_side_effect

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as session:
                with self.app.test_request_context():
                    data = {
                        'email': self.test_user_email,
                        'csrf_token': session.get_csrf_token(),
                    }
                    response = client.post('/reset/', data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)
                    state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

                    url = url_for('reset_password.config_reset_pw', _external=True)
                    data = {
                        'code': state.email_code.code,
                        'csrf_token': session.get_csrf_token(),
                    }
                    response = client.post(url, data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)

                    url = url_for('reset_password.choose_extra_security_phone', _external=True)
                    data = {'csrf_token': session.get_csrf_token(), 'code': state.email_code.code, 'phone_index': '0'}
                    response = client.post(url, data=json.dumps(data), content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)

                    client.set_cookie(
                        'localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie
                    )

                    eppn = quote_plus(self.test_user_eppn)

                    return client.get(f'/reset/get-phone-code?eppn={eppn}')

    # actual tests

    def test_get_zxcvbn_terms(self):
        with self.app.test_request_context():
            terms = get_zxcvbn_terms(self.test_user_eppn)
            self.assertEqual(terms, ['John', 'Smith', 'John', 'Smith', 'johnsmith', 'johnsmith2'])

    def test_get_zxcvbn_terms_no_given_name(self):
        with self.app.test_request_context():
            self.test_user.given_name = ''
            self.app.central_userdb.save(self.test_user, check_sync=False)
            terms = get_zxcvbn_terms(self.test_user_eppn)
            self.assertEqual(terms, ['John', 'Smith', 'Smith', 'johnsmith', 'johnsmith2'])

    def test_get_zxcvbn_terms_no_surname(self):
        with self.app.test_request_context():
            self.test_user.surname = ''
            self.app.central_userdb.save(self.test_user, check_sync=False)
            terms = get_zxcvbn_terms(self.test_user_eppn)
            self.assertEqual(terms, ['John', 'Smith', 'John', 'johnsmith', 'johnsmith2'])

    def test_get_zxcvbn_terms_no_display_name(self):
        with self.app.test_request_context():
            self.test_user.display_name = ''
            self.app.central_userdb.save(self.test_user, check_sync=False)
            terms = get_zxcvbn_terms(self.test_user_eppn)
            self.assertEqual(terms, ['John', 'Smith', 'johnsmith', 'johnsmith2'])

    def test_get_zxcvbn_terms_nonexistent(self):
        with self.app.test_request_context():
            with self.assertRaises(UserDoesNotExist):
                get_zxcvbn_terms('purra-porra')

    def test_app_starts(self):
        self.assertEqual(self.app.config.app_name, "reset_password")

    def test_post_email_address(self):
        response = self._post_email_address()
        self.assertEqual(response.status_code, 200)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertEqual(state.email_address, 'johnsmith@example.com')

    def test_post_email_address_sendmail_fail(self):
        from eduid_common.api.exceptions import MailTaskFailed

        response = self._post_email_address(sendmail_return=False, sendmail_side_effect=MailTaskFailed)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_FAIL')
        self.assertEqual(response.json['payload']['message'], 'resetpw.send-pw-fail')

    @patch('eduid_userdb.userdb.UserDB.get_user_by_mail')
    def test_post_email_uncomplete_signup(self, mock_get_user: Any):
        mock_get_user.side_effect = UserHasNotCompletedSignup('incomplete signup')
        response = self._post_email_address()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_FAIL')
        self.assertEqual(response.json['payload']['message'], 'resetpw.incomplete-user')

    def test_post_unknown_email_address(self):
        data = {'email': 'unknown@unplaced.un'}
        response = self._post_email_address(data1=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_FAIL')
        self.assertEqual(response.json['payload']['message'], 'resetpw.user-not-found')

    def test_post_email_address_wrong_csrf(self):
        data = {'csrf_token': 'wrong-token'}
        response = self._post_email_address(data1=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_FAIL')
        self.assertEqual(response.json['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_post_invalid_email_address(self):
        data = {'email': 'invalid-address'}
        response = self._post_email_address(data1=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_FAIL')
        self.assertEqual(response.json['payload']['error']['email'], ['Invalid email address'])

    def test_post_reset_code(self):
        response = self._post_reset_code()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['payload']['extra_security']['phone_numbers'][0]['number'], 'XXXXXXXXXX09')
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_CONFIG_SUCCESS')

    def test_post_reset_code_unknown_email(self):
        data1 = {'email': 'unknown@unknown.com'}
        with self.assertRaises(DocumentDoesNotExist):
            self._post_reset_code(data1=data1)

    def test_post_reset_code_no_extra_sec(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        # Unverify phone numbers
        for number in user.phone_numbers.verified.to_list():
            user.phone_numbers.remove(number.key)
        self.app.central_userdb.save(user)
        response = self._post_reset_code()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['payload']['extra_security'], {})
        self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_CONFIG_SUCCESS')

    def test_post_reset_wrong_code(self):
        data2 = {'code': 'wrong-code'}
        response = self._post_reset_code(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_CONFIG_FAIL', msg=ResetPwMsg.unknown_code
        )

    def test_post_reset_wrong_csrf(self):
        data2 = {'csrf_token': 'wrong-code'}
        response = self._post_reset_code(data2=data2)
        self._check_error_response(
            response, type_='POST_RESET_PASSWORD_RESET_CONFIG_FAIL', error={'csrf_token': ['CSRF failed to validate'],},
        )

    def test_post_reset_password(self):
        response = self._post_reset_password()
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SUCCESS', msg=ResetPwMsg.pw_resetted
        )

        # check that the user no longer has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        verified_phone_numbers = user.phone_numbers.verified.to_list()
        self.assertEqual(len(verified_phone_numbers), 0)
        verified_nins = user.nins.verified.to_list()
        self.assertEqual(len(verified_nins), 0)

        # check that the password is marked as generated
        self.assertTrue(user.credentials.to_list()[0].is_generated)

    def test_post_reset_password_no_data(self):
        response = self._post_reset_password(data2={})
        self._check_error_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_FAIL',
            error={
                'code': ['Missing data for required field.'],
                'csrf_token': ['Missing data for required field.'],
                'password': ['Missing data for required field.'],
            },
        )

    def test_post_reset_password_weak(self):
        data2 = {'password': 'pw'}
        response = self._post_reset_password(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_FAIL', msg=ResetPwMsg.chpass_weak
        )

    def test_post_reset_password_no_csrf(self):
        data2 = {'csrf_token': ''}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_FAIL',
            error={'csrf_token': ['CSRF failed to validate'],},
        )

    def test_post_reset_password_wrong_code(self):
        data2 = {'code': 'wrong-code'}
        response = self._post_reset_password(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_FAIL', msg=ResetPwMsg.unknown_code
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        verified_phone_numbers = user.phone_numbers.verified.to_list()
        self.assertEqual(len(verified_phone_numbers), 1)
        verified_nins = user.nins.verified.to_list()
        self.assertEqual(len(verified_nins), 2)

    def test_post_reset_password_custom(self):
        data2 = {'password': 'cust0m-p4ssw0rd'}
        response = self._post_reset_password(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SUCCESS', msg=ResetPwMsg.pw_resetted
        )

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[0].is_generated)

    def test_post_choose_extra_sec(self):
        response = self._post_choose_extra_sec()
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_SUCCESS', msg=ResetPwMsg.send_sms_success
        )

    def test_post_choose_extra_sec_sms_fail(self):
        self.app.config.throttle_sms_seconds = 300
        from eduid_common.api.exceptions import MsgTaskFailed

        response = self._post_choose_extra_sec(sendsms_side_effect=MsgTaskFailed())
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_FAIL', msg=ResetPwMsg.send_sms_failure
        )

    def test_post_choose_extra_sec_throttled(self):
        self.app.config.throttle_sms_seconds = 300
        response = self._post_choose_extra_sec(repeat=True)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_FAIL', msg=ResetPwMsg.send_sms_throttled
        )

    def test_post_choose_extra_sec_not_throttled(self):
        self.app.config.throttle_sms_seconds = 0
        response = self._post_choose_extra_sec(repeat=True)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_SUCCESS', msg=ResetPwMsg.send_sms_success
        )

    def test_post_choose_extra_sec_wrong_code(self):
        data2 = {'code': 'wrong-code'}
        response = self._post_choose_extra_sec(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_FAIL', msg=ResetPwMsg.email_not_validated
        )

    def test_post_choose_extra_sec_bad_phone_index(self):
        data3 = {'phone_index': '3'}
        with self.assertRaises(IndexError):
            self._post_choose_extra_sec(data3=data3)

    def test_post_choose_extra_sec_wrong_csrf_token(self):
        data3 = {'csrf_token': 'wrong-token'}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_FAIL',
            error={'csrf_token': ['CSRF failed to validate'],},
        )

    def test_post_choose_extra_sec_wrong_final_code(self):
        data3 = {'code': 'wrong-code'}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_PHONE_FAIL', msg=ResetPwMsg.unknown_code
        )

    def test_post_reset_password_secure_phone(self):
        response = self._post_reset_password_secure_phone()
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_SUCCESS', msg=ResetPwMsg.pw_resetted
        )

    @patch('eduid_webapp.reset_password.views.reset_password.verify_phone_number')
    def test_post_reset_password_secure_phone_verify_fail(self, mock_verify: Any):
        mock_verify.return_value = False
        response = self._post_reset_password_secure_phone()
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL', msg=ResetPwMsg.phone_invalid
        )

    def test_post_reset_password_secure_phone_wrong_csrf_token(self):
        data2 = {'csrf_token': 'wrong-code'}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL',
            error={'csrf_token': ['CSRF failed to validate']},
        )

    def test_post_reset_password_secure_phone_wrong_email_token(self):
        data2 = {'code': 'wrong-code'}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL', msg=ResetPwMsg.unknown_code
        )

    def test_post_reset_password_secure_phone_wrong_sms_token(self):
        data2 = {'phone_code': 'wrong-code'}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_success_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL',
            msg=ResetPwMsg.unknown_phone_code,
        )

    def test_post_reset_password_secure_phone_weak_password(self):
        data2 = {'password': 'pw'}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL', msg=ResetPwMsg.chpass_weak
        )

    def test_post_reset_password_secure_token(self):
        response = self._post_reset_password_secure_token()
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_SUCCESS', msg=ResetPwMsg.pw_resetted
        )

    def test_post_reset_password_secure_token_custom_pw(self):
        response = self._post_reset_password_secure_token(custom_password='T%7j 8/tT a0=b')
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_SUCCESS', msg=ResetPwMsg.pw_resetted
        )
        # TODO: Load the user from the database and verify the new credential has is_generated=False

    def test_post_reset_password_secure_token_no_data(self):
        response = self._post_reset_password_secure_token(data2={})
        self._check_error_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_FAIL',
            error={
                'code': ['Missing data for required field.'],
                'csrf_token': ['Missing data for required field.'],
                'password': ['Missing data for required field.'],
            },
        )

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('fido2.cose.ES256.verify')
    def test_post_reset_password_secure_token_wrong_credential(
        self, mock_verify, mock_request_user_sync, mock_get_vccs_client, mock_sendmail
    ):
        credential_data = {
            'credential_data': 'AAAAAAAAAAAAAAAAAAAAAABAi3KjBT0t5TPm693T0O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_aUBAgMmIAEhWCCiwDYGxl1LnRMqooWm0aRR9YbBG2LZ84BMNh_4rHkA9yJYIIujMrUOpGekbXjgMQ8M13ZsBD_cROSPB79eGz2Nw1ZE'
        }
        response = self._post_reset_password_secure_token(credential_data=credential_data)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_FAIL', msg=ResetPwMsg.fido_token_fail
        )

    def test_post_reset_password_secure_token_wrong_request(self):
        data2 = {'authenticatorData': 'Wrong-authenticatorData----UMmBLDxB7n3apMPQAAAAAAA'}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_FAIL', msg=ResetPwMsg.fido_token_fail
        )

    def test_post_reset_password_secure_token_wrong_csrf(self):
        data2 = {'csrf_token': 'wrong-code'}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_error_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_FAIL',
            error={'csrf_token': ['CSRF failed to validate']},
        )

    def test_post_reset_password_secure_token_wrong_code(self):
        data2 = {'code': 'wrong-code'}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_FAIL', msg=ResetPwMsg.unknown_code
        )

    def test_post_reset_password_secure_token_weak_password(self):
        data2 = {'password': 'pw'}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_TOKEN_FAIL', msg=ResetPwMsg.chpass_weak
        )

    def test_post_reset_password_secure_email_timeout(self):
        self.app.config.email_code_timeout = 0
        response = self._post_reset_password_secure_phone()
        self._check_success_response(
            response,
            type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL',
            msg=ResetPwMsg.expired_email_code,
        )

    def test_post_reset_password_secure_phone_timeout(self):
        self.app.config.phone_code_timeout = 0
        response = self._post_reset_password_secure_phone()
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_FAIL', msg=ResetPwMsg.expired_sms_code
        )

    def test_post_reset_password_secure_custom(self):
        data2 = {'password': 'other-password'}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_success_response(
            response, type_='POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_PHONE_SUCCESS', msg=ResetPwMsg.pw_resetted
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[0].is_generated)

    def test_get_code_backdoor(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        resp = self._get_email_code_backdoor()

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, state.email_code.code.encode('ascii'))

    def test_get_code_no_backdoor_in_pro(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'pro'

        resp = self._get_email_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = ''
        self.app.config.environment = 'dev'

        resp = self._get_email_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self):
        self.app.config.magic_cookie = ''
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        resp = self._get_email_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_phone_code_backdoor(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        resp = self._get_phone_code_backdoor()

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, state.phone_code.code.encode('ascii'))

    def test_get_phone_code_no_backdoor_in_pro(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'pro'

        resp = self._get_phone_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_phone_code_no_backdoor_misconfigured1(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = ''
        self.app.config.environment = 'dev'

        resp = self._get_phone_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_phone_code_no_backdoor_misconfigured2(self):
        self.app.config.magic_cookie = ''
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        resp = self._get_phone_code_backdoor()

        self.assertEqual(resp.status_code, 400)


class ChangePasswordTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_user_email = 'johnsmith@example.com'
        self.test_user_nin = '197801011235'
        super(ChangePasswordTests, self).setUp(copy_user_to_private=True)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_reset_password_app('testing', config)

    def update_config(self, config):
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},
                'vccs_url': 'http://vccs',
                'email_code_timeout': 7200,
                'phone_code_timeout': 600,
                'password_length': 12,
                'password_entropy': 25,
                'chpass_timeout': 600,
            }
        )
        return ResetPasswordConfig(**config)

    def tearDown(self):
        super(ChangePasswordTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    # parameterized test methods

    def _get_suggested(self):
        """
        GET a suggested password.
        """
        response = self.browser.get('/suggested-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:

            return client.get('/suggested-password')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _change_password(
        self,
        mock_request_user_sync: Any,
        reauthn: Optional[int] = None,
        data1: Optional[dict] = None,
        yuck_add_csrf: bool = False,
    ):
        """
        To change the pasword of the test user, POST old and new passwords,
        mocking the required reauthentication (by setting a flag in the session).

        :param reauthn: timestamp to set in the session, as the time at which the user
                        has re-authenticated.
        :param data1: to control the data sent to the change-password endpoint.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    if reauthn is not None:
                        sess['reauthn-for-chpass'] = reauthn

                    data = {'new_password': '0ieT/(.edW76', 'old_password': '5678', 'csrf_token': sess.get_csrf_token()}
                    if data1 == {}:
                        data = {}
                        if yuck_add_csrf:
                            data['csrf_token'] = sess.get_csrf_token()
                    elif data1 is not None:
                        data.update(data1)

                    return client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _get_suggested_and_change(
        self, mock_request_user_sync: Any, data1: Optional[dict] = None, authenticate: bool = True
    ):
        """
        To change the pasword of the test user using a suggested password,
        first GET a suggested password, and then POST old and new passwords,
        mocking the required reauthentication (by setting a flag in the session).

        :param reauthn: timestamp to set in the session, as the time at which the user
                        has re-authenticated.
        :param data1: to control the data sent to the change-password endpoint.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.add_credentials', return_value=True):
                        with patch(
                            'eduid_common.authn.vccs.vccs_client.VCCSClient.revoke_credentials', return_value=True
                        ):
                            with patch(
                                'eduid_common.authn.vccs.vccs_client.VCCSClient.authenticate', return_value=authenticate
                            ):
                                sess['reauthn-for-chpass'] = int(time.time())
                                response2 = client.get('/suggested-password')
                                passwd = json.loads(response2.data)
                                self.assertEqual(passwd['type'], 'GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS')
                                password = passwd['payload']['suggested_password']
                                sess.reset_password.generated_password_hash = hash_password(password)
                                sess.persist()
                                data = {
                                    'csrf_token': sess.get_csrf_token(),
                                    'new_password': password,
                                    'old_password': '5678',
                                }
                                if data1 is not None:
                                    data.update(data1)
                                return client.post(
                                    '/change-password', data=json.dumps(data), content_type=self.content_type_json
                                )

    # actual tests

    def test_app_starts(self):
        self.assertEqual(self.app.config.app_name, "reset_password")

    def test_get_suggested(self):
        response = self._get_suggested()
        passwd = json.loads(response.data)
        self.assertEqual(passwd['type'], "GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS")

    @patch('eduid_webapp.reset_password.views.change_password.change_password')
    def test_change_passwd(self, mock_change_password):
        mock_change_password.return_value = True

        reauthn = int(time.time())
        response = self._change_password(reauthn=reauthn)
        self._check_success_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS',
            # TODO: this endpoint does not return an ResetPwMsg
            # msg=ResetPwMsg.pw_resetted,
            msg=None,
        )
        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS")

    def test_change_passwd_no_data(self):
        response = self._change_password(data1={}, yuck_add_csrf=True)
        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL',
            error={
                'new_password': ['Missing data for required field.'],
                'old_password': ['Missing data for required field.'],
            },
        )

    def test_change_passwd_empty_data(self):
        data1 = {'new_password': '', 'old_password': ''}
        response = self._change_password(data1=data1)
        self._check_success_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL', msg=ResetPwMsg.chpass_no_data
        )

    def test_change_passwd_no_reauthn(self):
        response = self._change_password()
        self._check_success_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL', msg=ResetPwMsg.no_reauthn
        )

    def test_change_passwd_stale(self):
        response = self._change_password(reauthn=1)
        self._check_success_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL', msg=ResetPwMsg.stale_reauthn
        )

    @patch('eduid_webapp.reset_password.views.change_password.change_password')
    def test_change_passwd_no_csrf(self, mock_change_password):
        mock_change_password.return_value = True

        reauthn = int(time.time())
        data1 = {'csrf_token': ''}
        response = self._change_password(reauthn=reauthn, data1=data1)
        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL',
            error={'csrf_token': ['CSRF failed to validate'],},
        )

    @patch('eduid_webapp.reset_password.views.change_password.change_password')
    def test_change_passwd_wrong_csrf(self, mock_change_password):
        mock_change_password.return_value = True

        reauthn = int(time.time())
        data1 = {'csrf_token': 'wrong-token'}
        response = self._change_password(data1=data1, reauthn=reauthn)
        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL',
            error={'csrf_token': ['CSRF failed to validate'],},
        )

    @patch('eduid_webapp.reset_password.views.change_password.change_password')
    def test_change_passwd_weak(self, mock_change_password):
        mock_change_password.return_value = True

        reauthn = int(time.time())
        data1 = {'new_password': 'pw'}
        response = self._change_password(data1=data1, reauthn=reauthn)

        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")
        self.assertEqual(response.json['payload']['message'], 'chpass.weak-password')

    def test_get_suggested_and_change(self):
        response = self._get_suggested_and_change()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS")

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertTrue(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_custom(self):
        data1 = {'new_password': '0ieT/(.edW76'}
        response = self._get_suggested_and_change(data1=data1)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS")

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_wrong_csrf(self):
        data1 = {'csrf_token': 'wrong-token'}
        response = self._get_suggested_and_change(data1=data1)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")
        self.assertEqual(response.json['payload']['error']['csrf_token'], ['CSRF failed to validate'])

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_wrong_old_pw(self):
        response = self._get_suggested_and_change(authenticate=False)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")
        self.assertEqual(response.json['payload']['message'], 'chpass.unable-to-verify-old-password')

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_weak_new_pw(self):
        data1 = {'new_password': 'pw'}
        response = self._get_suggested_and_change(data1=data1)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['type'], "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")
        self.assertEqual(response.json['payload']['message'], 'chpass.weak-password')

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)
