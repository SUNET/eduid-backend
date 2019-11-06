# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import six
import datetime
import base64
import urllib
from collections import OrderedDict
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.cache import OutstandingQueriesCache
from eduid_webapp.eidas.settings.common import EidasConfig
from eduid_userdb import User
from eduid_userdb.credentials import U2F, Webauthn
from eduid_userdb.credentials.fido import FidoCredential
from eduid_userdb.data_samples import NEW_UNVERIFIED_USER_EXAMPLE

from eduid_webapp.eidas.app import init_eidas_app

__author__ = 'lundberg'

HERE = os.path.abspath(os.path.dirname(__file__))


class EidasTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_unverified_user_eppn = 'hubba-baar'
        self.test_user_nin = '197801011234'
        self.test_user_wrong_nin = '190001021234'
        self.test_idp = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
        self.mock_address = OrderedDict([
            (u'Name', OrderedDict([
                (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                (u'Surname', u'Testsson')])),
            (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                              (u'PostalCode', u'12345'),
                                              (u'City', u'LANDET')]))
        ])

        self.saml_response_tpl_success = """<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="{sp_url}saml2-acs" ID="id-88b9f586a2a3a639f9327485cc37c40a" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
  </samlp:Status>
  <saml:Assertion ID="id-093952102ceb73436e49cb91c58b0578" IssueInstant="{timestamp}" Version="2.0">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="" SPNameQualifier="{sp_url}saml2-metadata">1f87035b4c1325b296a53d92097e6b3fa36d7e30ee82e3fcb0680d60243c1f03</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{session_id}" NotOnOrAfter="{tomorrow}" Recipient="{sp_url}saml2-acs" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{yesterday}" NotOnOrAfter="{tomorrow}">
      <saml:AudienceRestriction>
        <saml:Audience>{sp_url}saml2-metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{timestamp}" SessionIndex="{session_id}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>http://id.elegnamnden.se/loa/1.0/loa3</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute FriendlyName="personalIdentityNumber" Name="urn:oid:1.2.752.29.4.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">{asserted_nin}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">Ülla Älm</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">Ûlla</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="dateOfBirth" Name="urn:oid:1.3.6.1.5.5.7.9.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">1978-01-01</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">Älm</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
        self.saml_response_tpl_fail = """<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{sp_url}saml2-acs" ID="_ebad01e547857fa54927b020dba1edb1" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml2:Issuer>  
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
      <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" />
    </saml2p:StatusCode>
    <saml2p:StatusMessage>User login was not successful or could not meet the requirements of the requesting application.</saml2p:StatusMessage>
  </saml2p:Status>
</saml2p:Response>"""
        self.saml_response_tpl_cancel = """
        <?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{sp_url}saml2-acs" ID="_ebad01e547857fa54927b020dba1edb1" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml2:Issuer>  
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
      <saml2p:StatusCode Value="http://id.elegnamnden.se/status/1.0/cancel" />
    </saml2p:StatusCode>
    <saml2p:StatusMessage>The login attempt was cancelled</saml2p:StatusMessage>
  </saml2p:Status>
</saml2p:Response>"""

        super(EidasTests, self).setUp(users=['hubba-bubba', 'hubba-baar'])

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_eidas_app('testing', config)

    def update_config(self, app_config):
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        app_config.update({
            'token_verify_redirect_url': 'http://test.localhost/profile',
            'nin_verify_redirect_url': 'http://test.localhost/profile',
            'action_url': 'http://idp.test.localhost/action',
            'msg_broker_url': 'amqp://dummy',
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
            'saml2_settings_module': saml_config,
            'safe_relay_domain': 'localhost',
            'authentication_context_map': {
                'loa1': 'http://id.elegnamnden.se/loa/1.0/loa1',
                'loa2': 'http://id.elegnamnden.se/loa/1.0/loa2',
                'loa3': 'http://id.elegnamnden.se/loa/1.0/loa3',
                'uncertified-loa3': 'http://id.swedenconnect.se/loa/1.0/uncertified-loa3',
                'loa4': 'http://id.elegnamnden.se/loa/1.0/loa4',
                'eidas-low': 'http://id.elegnamnden.se/loa/1.0/eidas-low',
                'eidas-sub': 'http://id.elegnamnden.se/loa/1.0/eidas-sub',
                'eidas-high': 'http://id.elegnamnden.se/loa/1.0/eidas-high',
                'eidas-nf-low': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-low',
                'eidas-nf-sub': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-sub',
                'eidas-nf-high': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-high'
            },
            'authn_sign_alg': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'authn_digest_alg': 'http://www.w3.org/2001/04/xmlenc#sha256'
            })
        return EidasConfig(**app_config)

    def add_token_to_user(self, eppn, credential_id, token_type):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        if token_type == 'u2f':
            mfa_token = U2F(version='test', keyhandle=credential_id, public_key='test', app_id='test',
                            attest_cert='test', description='test', application='test')
        else:
            mfa_token = Webauthn(keyhandle=credential_id, credential_data='test', app_id='test', attest_obj='test',
                                 description='test', application='test')
        user.credentials.add(mfa_token)
        self.request_user_sync(user)
        return mfa_token

    @staticmethod
    def generate_auth_response(session_id, saml_response_tpl, asserted_nin=None):
        """
        Generates a fresh signed authentication response
        """

        timestamp = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        tomorrow = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)

        sp_baseurl = 'http://test.localhost:6544/'

        resp = ' '.join(saml_response_tpl.format(**{
            'asserted_nin': asserted_nin,
            'session_id': session_id,
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'tomorrow': tomorrow.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'yesterday': yesterday.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'sp_url': sp_baseurl,
        }).split())

        if six.PY3:
            # Needs to be bytes
            return resp.encode('utf-8')
        return resp

    def test_authenticate(self):
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/')
        self.assertEqual(response.status_code, 200)  # Authenticated request

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_u2f_token_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'u2f')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success, self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                user_mfa_tokens = user.credentials.filter(U2F).to_list()

                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, True)

                self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_webauthn_token_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'webauthn')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success, self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                user_mfa_tokens = user.credentials.filter(Webauthn).to_list()

                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, True)

                self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_mfa_token_verify_wrong_verified_nin(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'u2f')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success,
                                                             self.test_user_wrong_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                user_mfa_tokens = user.credentials.filter(FidoCredential).to_list()

                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, False)

                self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_mfa_token_verify_no_verified_nin(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_unverified_user_eppn, 'test', 'webauthn')
        user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)
        self.assertEqual(user.nins.verified.count, 0)

        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success, self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)
                user_mfa_tokens = user.credentials.filter(FidoCredential).to_list()
                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, True)

                self.assertEqual(user.nins.verified.count, 1)
                self.assertEqual(user.nins.primary.number, self.test_user_nin)

                self.assertEqual(self.app.proofing_log.db_count(), 2)

    def test_mfa_token_verify_no_mfa_login(self):
        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'u2f')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = ['other_id']
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                self.assertEqual(response.status_code, 302)
                self.assertEqual(
                    response.location,
                    'http://test.localhost/reauthn?next=http://test.localhost/verify-token/{}?idp={}'.format(
                        credential.key, self.test_idp))

    def test_mfa_token_verify_no_mfa_token_in_session(self):
        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'webauthn')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success, self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess['eduidIdPCredentialsUsed'] = ['other_id']
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                response = browser.post('/saml2-acs', data=data)

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location,
                                 '{}?msg=%3AERROR%3Aeidas.token_not_in_credentials_used'.format(
                                     self.app.config.token_verify_redirect_url))

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_mfa_token_verify_aborted_auth(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'u2f')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_fail,
                                                             self.test_user_wrong_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                user_mfa_tokens = user.credentials.filter(FidoCredential).to_list()

                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, False)

                self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_mfa_token_verify_cancel_auth(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'webauthn')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_cancel,
                                                             self.test_user_wrong_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                user_mfa_tokens = user.credentials.filter(FidoCredential).to_list()

                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, False)

                self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_mfa_token_verify_auth_fail(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = self.add_token_to_user(self.test_user_eppn, 'test', 'u2f')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['eduidIdPCredentialsUsed'] = [credential.key, 'other_id']
                sess.persist()
                response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_fail,
                                                             self.test_user_wrong_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'token-verify-action'
                sess['verify_token_action_credential_id'] = credential.key
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
                user_mfa_tokens = user.credentials.filter(FidoCredential).to_list()

                self.assertEqual(len(user_mfa_tokens), 1)
                self.assertEqual(user_mfa_tokens[0].is_verified, False)

                self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_nin_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)
        self.assertEqual(user.nins.verified.count, 0)

        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            with browser.session_transaction() as sess:
                response = browser.get('/verify-nin?idp={}'.format(self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success,
                                                             self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'nin-verify-action'
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)

                self.assertEqual(user.nins.verified.count, 1)
                self.assertEqual(user.nins.primary.number, self.test_user_nin)

                self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_nin_verify_already_verified(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)
        self.assertEqual(user.nins.verified.count, 0)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                response = browser.get('/verify-nin/?idp={}'.format(self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success, self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'nin-verify-action'
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                response = browser.post('/saml2-acs', data=data)

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location,
                                 '{}?msg=%3AERROR%3Aeidas.nin_already_verified'.format(
                                     self.app.config.nin_verify_redirect_url))

    def test_mfa_authentication_verified_user(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertNotEqual(user.nins.verified.count, 0)

        next_url = base64.b64encode(b'http://idp.localhost/action').decode('utf-8')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                response = browser.get('/mfa-authentication/?idp={}&next={}'.format(self.test_idp, next_url))
                self.assertEqual(response.status_code, 302)

                ps = urllib.parse.urlparse(response.location)
                qs = urllib.parse.parse_qs(ps.query)
                relay_state = qs['RelayState'][0]
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success, self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, relay_state)
                sess['post-authn-action'] = 'mfa-authentication-action'
                sess['eidas_redirect_urls'] = {relay_state: next_url}

            data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': relay_state}
            response = browser.post('/saml2-acs', data=data)

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location,
                             'http://idp.localhost/action/redirect-action?msg=actions.action-completed')

    def test_mfa_authentication_wrong_nin(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertNotEqual(user.nins.verified.count, 0)

        next_url = base64.b64encode(b'http://idp.localhost/action').decode('utf-8')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                response = browser.get('/mfa-authentication/?idp={}&next={}'.format(self.test_idp, next_url))
                self.assertEqual(response.status_code, 302)

                ps = urllib.parse.urlparse(response.location)
                qs = urllib.parse.parse_qs(ps.query)
                relay_state = qs['RelayState'][0]
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success,
                                                             self.test_user_wrong_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, relay_state)
                sess['post-authn-action'] = 'mfa-authentication-action'
                sess['eidas_redirect_urls'] = {relay_state: next_url}

            data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': relay_state}
            response = browser.post('/saml2-acs', data=data)

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location,
                             'http://idp.localhost/action?msg=%3AERROR%3Aeidas.nin_not_matching')

    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_nin_staging_remap_verify(self, mock_request_user_sync, mock_get_postal_address):
        self.app.config.environment = 'staging'
        self.app.config.staging_nin_map = {
            self.test_user_nin: '190102031234'
        }

        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)
        self.assertEqual(user.nins.verified.count, 0)

        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            with browser.session_transaction() as sess:
                response = browser.get('/verify-nin?idp={}'.format(self.test_idp))
                token = sess._session.token
                if isinstance(token, six.binary_type):
                    token = token.decode('ascii')
                authn_response = self.generate_auth_response(token, self.saml_response_tpl_success,
                                                             self.test_user_nin)
                oq_cache = OutstandingQueriesCache(sess)
                oq_cache.set(token, '/')
                sess['post-authn-action'] = 'nin-verify-action'
                sess.persist()

                self.assertEqual(response.status_code, 302)

                data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': '/'}
                browser.post('/saml2-acs', data=data)

                user = self.app.central_userdb.get_user_by_eppn(self.test_unverified_user_eppn)

                self.assertEqual(user.nins.verified.count, 1)
                self.assertEqual(user.nins.primary.number, '190102031234')

                self.assertEqual(self.app.proofing_log.db_count(), 1)

