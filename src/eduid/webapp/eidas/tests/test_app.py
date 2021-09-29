# -*- coding: utf-8 -*-

import base64
import datetime
import logging
import os
from collections import OrderedDict
from typing import Any, List, Mapping, Optional, Tuple
from unittest import TestCase
from urllib.parse import parse_qs, quote_plus, urlparse, urlunparse
from uuid import uuid4

from flask import Response
from mock import patch

from eduid.common.config.base import EduidEnvironment
from eduid.userdb import LockedIdentityNin, Nin
from eduid.userdb.credentials import U2F, Webauthn
from eduid.userdb.credentials.fido import FidoCredential
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.messages import TranslatableMsg, redirect_with_msg
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction, EidasAcsAction
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.session import EduidSession
from eduid.webapp.common.session.namespaces import AuthnRequestRef, MfaActionError, SP_AuthnRequest
from eduid.webapp.eidas.app import EidasApp, init_eidas_app
from eduid.webapp.eidas.helpers import EidasMsg

__author__ = 'lundberg'

from saml2.time_util import utc_now

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class EidasTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    app: EidasApp

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_unverified_user_eppn = 'hubba-baar'
        self.test_user_nin = '197801011234'
        self.test_user_wrong_nin = '190001021234'
        self.test_idp = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
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
      {extra_attributes}
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

        super().setUp(users=['hubba-bubba', 'hubba-baar'])

    def load_app(self, config: Mapping[str, Any]) -> EidasApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_eidas_app('testing', config)

    def update_config(self, app_config):
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        app_config.update(
            {
                'token_verify_redirect_url': 'http://test.localhost/profile',
                'nin_verify_redirect_url': 'http://test.localhost/profile',
                'action_url': 'http://idp.test.localhost/action',
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
                    'eidas-nf-high': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-high',
                },
                'authn_sign_alg': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                'authn_digest_alg': 'http://www.w3.org/2001/04/xmlenc#sha256',
                'magic_cookie': '',
                'magic_cookie_name': 'magic-cookie',
                'environment': 'dev',
            }
        )
        return app_config

    def add_token_to_user(self, eppn, credential_id, token_type):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        if token_type == 'u2f':
            mfa_token = U2F(
                version='test',
                keyhandle=credential_id,
                public_key='test',
                app_id='test',
                attest_cert='test',
                description='test',
                created_by='test',
            )
        else:
            mfa_token = Webauthn(
                keyhandle=credential_id,
                credential_data='test',
                app_id='test',
                attest_obj='test',
                description='test',
                created_by='test',
            )
        user.credentials.add(mfa_token)
        self.request_user_sync(user)
        return mfa_token

    @staticmethod
    def generate_auth_response(
        request_id: str,
        saml_response_tpl: str,
        asserted_nin=None,
        age: int = 10,
        credentials_used: Optional[List[ElementKey]] = None,
    ) -> bytes:
        """
        Generates a fresh signed authentication response
        """

        timestamp = datetime.datetime.utcnow() - datetime.timedelta(seconds=age)
        tomorrow = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)

        sp_baseurl = 'http://test.localhost:6544/'

        extra_attributes = []

        if credentials_used:
            for cred in credentials_used:
                this = f"""
                       <saml:Attribute Name="eduidIdPCredentialsUsed"
                                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                           <saml:AttributeValue xsi:type="xs:string">{cred}</saml:AttributeValue>
                       </saml:Attribute>
                       """
                extra_attributes += [this]

        extra_attributes_str = '\n'.join(extra_attributes)

        resp = ' '.join(
            saml_response_tpl.format(
                **{
                    'asserted_nin': asserted_nin,
                    'session_id': request_id,
                    'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'tomorrow': tomorrow.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'yesterday': yesterday.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'sp_url': sp_baseurl,
                    'extra_attributes': extra_attributes_str,
                }
            ).split()
        )

        return resp.encode('utf-8')

    def _session_setup(
        self,
        session: EduidSession,
        action: EidasAcsAction,
        req_id: Optional[str] = None,
        relay_state: str = '/',
        verify_token: Optional[ElementKey] = None,
        credentials_used: Optional[List[ElementKey]] = None,
    ) -> None:
        assert isinstance(session, EduidSession)
        if req_id is not None:
            oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
            oq_cache.set(req_id, relay_state)
        session.eidas.sp.post_authn_action = action
        if verify_token is not None:
            logger.debug(f'Test setting verify_token_action_credential_id in session {session}: {verify_token}')
            session.eidas.verify_token_action_credential_id = verify_token
        if credentials_used is not None:
            self._setup_faked_login(session=session, credentials_used=credentials_used)

    def _setup_faked_login(self, session: EduidSession, credentials_used: List[ElementKey]) -> None:
        logger.debug(f'Test setting credentials used for login in session {session}: {credentials_used}')
        _authn_id = AuthnRequestRef(str(uuid4()))
        session.authn.sp.authns[_authn_id] = SP_AuthnRequest(
            post_authn_action=AuthnAcsAction.login,
            credentials_used=credentials_used,
            authn_instant=utc_now(),
            redirect_url='/',
        )

    def _get_request_id_from_session(self, session: EduidSession) -> Tuple[str, AuthnRequestRef]:
        """ extract the (probable) SAML request ID from the session """
        oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
        ids = oq_cache.outstanding_queries().keys()
        logger.debug(f'Outstanding queries for eidas in session {session}: {ids}')
        if len(ids) != 1:
            raise RuntimeError('More or less than one authn request in the session')
        saml_req_id = list(ids)[0]
        req_ref = AuthnRequestRef(oq_cache.outstanding_queries()[saml_req_id])
        return saml_req_id, req_ref

    def _verify_redirect_url(
        self, response: Response, expect_msg: TranslatableMsg, expect_error: bool, expect_redirect_url: str
    ) -> None:
        assert response.status_code == 302

        logger.debug(f'Verifying returned location {response.location}')

        ps = urlparse(response.location)
        # Check the base part of the URL (everything except the query string)
        _ps = ps._replace(query='')  # type: ignore
        redirect_url_no_params = urlunparse(_ps)
        assert redirect_url_no_params == expect_redirect_url
        # Check the msg in the query string
        qs = parse_qs(str(ps.query))
        if expect_error:
            assert qs['msg'] == [f':ERROR:{expect_msg.value}']
        else:
            assert qs['msg'] == [expect_msg.value]

    def _verify_user_parameters(
        self,
        eppn: str,
        num_mfa_tokens: int = 1,
        is_verified: bool = False,
        num_proofings: int = 0,
        nin: Optional[str] = None,
        locked_nin: Optional[str] = None,
        nin_present: bool = True,
        nin_verified: bool = False,
        num_verified_nins: Optional[int] = None,
        at_least_one_verified_nin: Optional[bool] = None,
    ):
        """ This function is used to verify a user's parameters at the start of a test case,
        and then again at the end to ensure the right set of changes occurred to the user in the database.
         """
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        user_mfa_tokens = user.credentials.filter(FidoCredential)

        # Check token status
        assert len(user_mfa_tokens) == num_mfa_tokens, 'Unexpected number of FidoCredentials on user'
        if user_mfa_tokens:
            assert user_mfa_tokens[0].is_verified == is_verified, 'User token unexpected is_verified'
        assert self.app.proofing_log.db_count() == num_proofings, 'Unexpected number of proofings in db'

        if num_verified_nins is not None:
            # Check number of verified nins
            assert (
                len(user.nins.verified) == num_verified_nins
            ), f'User does not have {num_verified_nins} verified NINs (has {len(user.nins.verified)})'

        if at_least_one_verified_nin is True:
            assert len(user.nins.verified) != 0, 'User was expected to have at least one verified NIN'

        if nin is not None:
            # Check parameters of a specific nin
            _match = [x for x in user.nins.to_list() if x.number == nin]
            if not nin_present:
                assert not _match, f'NIN {nin} not expected to be present on user'
                return None
            assert _match, f'NIN {nin} not present on user'
            _nin = _match[0]
            assert isinstance(_nin, Nin)
            assert _nin.is_verified == nin_verified

        if locked_nin is not None:
            # Check parameters of a specific locked nin
            locked_identity = user.locked_identity.find('nin')
            assert locked_identity is not None, f'locked NIN {locked_nin} not present'
            if isinstance(locked_identity, LockedIdentityNin):
                assert (
                    locked_identity.number == locked_nin
                ), f'locked NIN {locked_identity.number} not matching {locked_nin}'

    def reauthn(
        self,
        endpoint: str,
        expect_msg: TranslatableMsg,
        expect_mfa_action_error: Optional[MfaActionError] = None,
        eppn: Optional[str] = None,
        age: int = 10,
        nin: Optional[str] = None,
        logged_in: bool = True,
        next_url: Optional[str] = None,
        expect_error: bool = False,
        expect_redirect_url: Optional[str] = None,
    ) -> None:
        if expect_redirect_url is None:
            expect_redirect_url = self.app.conf.action_url
        return self._call_endpoint_and_saml_acs(
            endpoint=endpoint,
            eppn=eppn,
            expect_msg=expect_msg,
            expect_mfa_action_error=expect_mfa_action_error,
            expect_error=expect_error,
            expect_redirect_url=expect_redirect_url,
            age=age,
            nin=nin,
            logged_in=logged_in,
            next_url=next_url,
        )

    def verify_token(
        self,
        endpoint: str,
        expect_msg: TranslatableMsg,
        eppn: Optional[str] = None,
        expect_error: bool = False,
        expect_saml_error: bool = False,
        expect_redirect_url: Optional[str] = None,
        age: int = 10,
        nin: Optional[str] = None,
        response_template: Optional[str] = None,
        credentials_used: Optional[List[ElementKey]] = None,
        verify_credential: Optional[ElementKey] = None,
    ) -> None:
        if expect_redirect_url is None:
            expect_redirect_url = self.app.conf.token_verify_redirect_url
        return self._call_endpoint_and_saml_acs(
            endpoint=endpoint,
            eppn=eppn,
            expect_msg=expect_msg,
            expect_error=expect_error,
            expect_saml_error=expect_saml_error,
            expect_redirect_url=expect_redirect_url,
            age=age,
            nin=nin,
            response_template=response_template,
            credentials_used=credentials_used,
            verify_credential=verify_credential,
        )

    def _call_endpoint_and_saml_acs(
        self,
        endpoint: str,
        eppn: Optional[str],
        expect_msg: TranslatableMsg,
        expect_redirect_url: str,
        expect_mfa_action_error: Optional[MfaActionError] = None,
        expect_error: bool = False,
        expect_saml_error: bool = False,
        age: int = 10,
        nin: Optional[str] = None,
        logged_in: bool = True,
        next_url: Optional[str] = None,
        response_template: Optional[str] = None,
        credentials_used: Optional[List[ElementKey]] = None,
        verify_credential: Optional[ElementKey] = None,
    ) -> None:

        if eppn is None:
            eppn = self.test_user_eppn

        if nin is None:
            nin = self.test_user_nin

        if response_template is None:
            response_template = self.saml_response_tpl_success

        if next_url is None:
            next_url = self.app.conf.action_url
        next_url = quote_plus(bytes(next_url, 'utf-8'))

        browser_with_session_cookie = self.session_cookie(self.browser, eppn)
        if not logged_in:
            browser_with_session_cookie = self.session_cookie_anon(self.browser)

        with browser_with_session_cookie as browser:
            if credentials_used:
                with browser.session_transaction() as sess:
                    self._setup_faked_login(session=sess, credentials_used=credentials_used)

            if logged_in is False:
                with browser.session_transaction() as sess:
                    # the user is at least partial logged in at this stage
                    sess.common.eppn = eppn

            _url = f'{endpoint}/?idp={self.test_idp}&next={next_url}'
            logger.debug(f'Test fetching url: {_url}')
            response = browser.get(_url)
            logger.debug(f'Test fetched url {_url}, response: {response}')
            assert response.status_code == 302

            with browser.session_transaction() as sess:
                request_id, authn_ref = self._get_request_id_from_session(sess)

            authn_response = self.generate_auth_response(
                request_id, response_template, asserted_nin=nin, age=age, credentials_used=credentials_used
            )
            if verify_credential:
                logger.debug(
                    f'Test setting verify_token_action_credential_id = {verify_credential} '
                    f'(was: {sess.eidas.verify_token_action_credential_id})'
                )
                with browser.session_transaction() as sess:
                    sess.eidas.verify_token_action_credential_id = verify_credential

            data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': ''}
            response = browser.post('/saml2-acs', data=data)

            if expect_mfa_action_error is not None:
                with browser.session_transaction() as sess:
                    assert sess.mfa_action.error == expect_mfa_action_error

        if expect_saml_error:
            assert response.status_code == 400
            return

        self._verify_redirect_url(
            response=response,
            expect_msg=expect_msg,
            expect_error=expect_error,
            expect_redirect_url=expect_redirect_url,
        )

    def test_authenticate(self):
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get('/')
        self._check_success_response(response, type_='GET_EIDAS_SUCCESS')

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_u2f_token_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        credential = self.add_token_to_user(eppn, 'test', 'u2f')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
        )

        self._verify_user_parameters(eppn, is_verified=True, num_proofings=1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_webauthn_token_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn

        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
        )

        self._verify_user_parameters(eppn, is_verified=True, num_proofings=1)

    def test_mfa_token_verify_wrong_verified_nin(self):
        eppn = self.test_user.eppn
        nin = self.test_user_wrong_nin
        credential = self.add_token_to_user(eppn, 'test', 'u2f')

        self._verify_user_parameters(eppn, nin=nin, nin_present=False)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.nin_not_matching,
            expect_error=True,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            nin=nin,
        )

        self._verify_user_parameters(eppn, nin=nin, nin_present=False)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_token_verify_no_verified_nin(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_user_nin
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn, num_verified_nins=0)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            nin=nin,
        )

        # Verify the user now has a verified NIN
        self._verify_user_parameters(
            eppn, is_verified=True, num_proofings=2, num_verified_nins=1, nin=nin, nin_verified=True
        )

    def test_mfa_token_verify_no_mfa_login(self):
        eppn = self.test_user.eppn
        credential = self.add_token_to_user(eppn, 'test', 'u2f')

        self._verify_user_parameters(eppn)

        with self.session_cookie(self.browser, eppn) as browser:
            response = browser.get('/verify-token/{}?idp={}'.format(credential.key, self.test_idp))
            assert response.status_code == 302
            assert response.location == (
                'http://test.localhost/reauthn?next='
                f'http://test.localhost/verify-token/{credential.key}?idp={self.test_idp}'
            )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_no_mfa_token_in_session(self):
        eppn = self.test_user.eppn
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.token_not_in_creds,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_aborted_auth(self):
        eppn = self.test_user.eppn
        credential = self.add_token_to_user(eppn, 'test', 'u2f')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_cancel_auth(self):
        eppn = self.test_user.eppn

        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            nin=self.test_user_wrong_nin,
            response_template=self.saml_response_tpl_cancel,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_auth_fail(self):
        eppn = self.test_user.eppn

        credential = self.add_token_to_user(eppn, 'test', 'u2f')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            nin=self.test_user_wrong_nin,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0)

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_verify_success,
            eppn=eppn,
            expect_redirect_url='http://test.localhost/profile',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=1, num_proofings=1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_login(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=2)

        self.reauthn(
            '/mfa-authentication',
            expect_msg=EidasMsg.action_completed,
            eppn=eppn,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=2, num_proofings=0)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_login_no_nin(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0, is_verified=False)

        self.reauthn(
            '/mfa-authentication',
            expect_msg=EidasMsg.nin_not_matching,
            expect_error=True,
            eppn=eppn,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0, num_proofings=0)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_login_unverified_nin(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn

        # Add locked nin to user
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        locked_nin = LockedIdentityNin(created_by='test', number=self.test_user_nin)
        user.locked_identity.add(locked_nin)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0, is_verified=False)

        self.reauthn(
            '/mfa-authentication',
            expect_msg=EidasMsg.action_completed,
            eppn=eppn,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=1, num_proofings=1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify_backdoor(self, mock_request_user_sync: Any, mock_get_postal_address: Any):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_user_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0)

        self.app.conf.magic_cookie = 'magic-cookie'

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            browser.set_cookie('localhost', key='nin', value=nin)
            browser.get(f'/verify-nin?idp={self.test_idp}')

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, num_verified_nins=1, nin=nin, nin_verified=True, num_proofings=1
        )

    def test_nin_verify_no_backdoor_in_pro(self):
        eppn = self.test_unverified_user_eppn
        nin = self.test_user_nin

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0)

        self.app.conf.magic_cookie = 'magic-cookie'
        self.app.conf.environment = EduidEnvironment.production

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            browser.set_cookie('localhost', key='nin', value=nin)

            browser.get(f'/verify-nin?idp={self.test_idp}')

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0, num_proofings=0)

    def test_nin_verify_no_backdoor_misconfigured(self):
        eppn = self.test_unverified_user_eppn
        nin = self.test_user_nin

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0)

        self.app.conf.magic_cookie = 'magic-cookie'

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value='NOT-the-magic-cookie')
            browser.set_cookie('localhost', key='nin', value=nin)
            browser.get(f'/verify-nin?idp={self.test_idp}')

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0)

    def test_nin_verify_already_verified(self):
        # Verify that the test user has a verified NIN in the database already
        eppn = self.test_user.eppn
        nin = self.test_user_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, nin=nin, nin_verified=True)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.nins.verified) != 0

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_already_verified,
            expect_error=True,
            expect_redirect_url='http://test.localhost/profile',
            nin=nin,
        )

    def test_mfa_authentication_verified_user(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.nins.verified) != 0, 'User was expected to have a verified NIN'

        self.reauthn(
            endpoint='/mfa-authentication',
            expect_msg=EidasMsg.action_completed,
            expect_redirect_url=self.app.conf.action_url,
        )

    def test_mfa_authentication_too_old_authn_instant(self):
        self.reauthn(
            endpoint='/mfa-authentication',
            age=61,
            expect_msg=EidasMsg.reauthn_expired,
            expect_mfa_action_error=MfaActionError.authn_too_old,
            expect_error=True,
        )

    def test_mfa_authentication_wrong_nin(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert len(user.nins.verified) != 0, 'User was expected to have a verified NIN'

        self.reauthn(
            endpoint='/mfa-authentication',
            expect_msg=EidasMsg.nin_not_matching,
            expect_mfa_action_error=MfaActionError.nin_not_matching,
            expect_error=True,
            nin=self.test_user_wrong_nin,
        )

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_postal_address')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_staging_remap_verify(self, mock_request_user_sync, mock_get_postal_address):
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        remapped_nin = '190102031234'
        self.app.conf.environment = EduidEnvironment.staging
        self.app.conf.staging_nin_map = {self.test_user_nin: remapped_nin}

        self._verify_user_parameters(eppn, num_mfa_tokens=0, num_verified_nins=0, nin=remapped_nin, nin_present=False)

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_verify_success,
            eppn=eppn,
            expect_redirect_url='http://test.localhost/profile',
            nin=self.test_user_nin,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, num_verified_nins=1, nin=remapped_nin, nin_verified=True, num_proofings=1
        )


class RedirectWithMsgTests(TestCase):
    def test_redirect_with_message(self):
        url = "https://www.exaple.com/services/eidas/?next=/authn"
        response = redirect_with_msg(url, EidasMsg.authn_context_mismatch)
        self.assertEqual(
            response.location,
            'https://www.exaple.com/services/eidas/?next=%2Fauthn&msg=%3AERROR%3Aeidas.authn_context_mismatch',
        )
