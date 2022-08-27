# -*- coding: utf-8 -*-

import base64
import datetime
import logging
import os
from typing import Any, List, Mapping, Optional, Tuple, Union
from unittest import TestCase
from urllib.parse import parse_qs, quote_plus, urlparse, urlunparse
from uuid import uuid4

from flask import Response
from flask.testing import FlaskClient
from mock import patch

from eduid.common.config.base import EduidEnvironment
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, DeregistrationInformation, OfficialAddress
from eduid.userdb import NinIdentity
from eduid.userdb.credentials import U2F, Webauthn
from eduid.userdb.credentials.external import SwedenConnectCredential
from eduid.userdb.credentials.fido import FidoCredential, WebauthnAuthenticator
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import EIDASIdentity, EIDASLoa, IdentityElement, PridPersistence
from eduid.webapp.authn.views import FALLBACK_FRONTEND_ACTION
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg, redirect_with_msg
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
        self.test_user_nin = NinIdentity(
            number='197801011234', date_of_birth=datetime.datetime.fromisoformat('1978-01-01')
        )
        self.test_user_eidas = EIDASIdentity(
            prid='XB:1bjrk7depnmhu7xn56kon3mlc9q1s0',
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat('1964-12-31'),
            country_code='XB',
        )
        self.test_user_wrong_nin = NinIdentity(
            number='190001021234', date_of_birth=datetime.datetime.fromisoformat('1900-01-02')
        )
        self.test_user_other_eidas = EIDASIdentity(
            prid='XA:some_other_prid',
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat('1920-11-18'),
            country_code='XA',
        )
        self.test_backdoor_nin = NinIdentity(
            number='190102031234', date_of_birth=datetime.datetime.fromisoformat('1901-02-03')
        )
        self.test_idp = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
        self.default_redirect_url = 'http://redirect.localhost/redirect'

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
        <saml:AttributeValue xsi:type="xs:string">{asserted_identity}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">Ülla Älm</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">Ûlla</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="dateOfBirth" Name="urn:oid:1.3.6.1.5.5.7.9.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">{date_of_birth}</saml:AttributeValue>
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
        self.saml_response_foreign_eid_tpl_success = """
        <?xml version='1.0' encoding='UTF-8'?>
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
        <saml:AuthnContextClassRef>http://id.elegnamnden.se/loa/1.0/eidas-nf-sub</saml:AuthnContextClassRef>
        <saml:AuthenticatingAuthority>https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:AuthenticatingAuthority>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute FriendlyName="c" Name="urn:oid:2.5.4.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">XB</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="pridPersistence" Name="urn:oid:1.2.752.201.3.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">B</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="givenName" Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">Javier</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="transactionIdentifier" Name="urn:oid:1.2.752.201.3.2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">_AbZv3Bk5c4d5n0LhvlXqaoTAQCJywBbOBx8Vf58gHL9uroDL7Jfez2tLxqIegCT</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="prid" Name="urn:oid:1.2.752.201.3.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">{asserted_identity}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="eidasPersonIdentifier" Name="urn:oid:1.2.752.201.3.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">XB/SE/ZWRlbiBSb290IENlcnRpZmljYXRpb24g</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="dateOfBirth" Name="urn:oid:1.3.6.1.5.5.7.9.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">{date_of_birth}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="sn" Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">Garcia</saml:AttributeValue>
      </saml:Attribute>
      {extra_attributes}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

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
                'identity_verify_redirect_url': 'http://test.localhost/profile',
                'saml2_settings_module': saml_config,
                'safe_relay_domain': 'localhost',
                'magic_cookie': '',
                'magic_cookie_name': 'magic-cookie',
                'magic_cookie_idp': self.test_idp,
                'environment': 'dev',
                'freja_idp': self.test_idp,
                'frontend_action_finish_url': {
                    'token_verify_redirect': 'http://test.localhost/profile',
                    'identity_verify_redirect': 'http://test.localhost/profile',
                },
            }
        )
        return app_config

    def add_token_to_user(self, eppn: str, credential_id: str, token_type) -> Union[U2F, Webauthn]:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        # please mypy
        assert user is not None
        mfa_token: Union[U2F, Webauthn]
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
                description='test',
                created_by='test',
                authenticator=WebauthnAuthenticator.cross_platform,
            )
        user.credentials.add(mfa_token)
        self.request_user_sync(user)
        return mfa_token

    def add_nin_to_user(self, eppn: str, nin: str, verified: bool) -> NinIdentity:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        # please mypy
        assert user is not None
        nin_element = NinIdentity(number=nin, created_by='test', is_verified=verified)
        user.identities.add(nin_element)
        self.request_user_sync(user)
        return nin_element

    def set_eidas_for_user(self, eppn: str, identity: EIDASIdentity, verified: bool) -> None:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        # please mypy
        assert user is not None
        identity.is_verified = verified
        user.identities.replace(element=identity)
        if verified is True:
            user.locked_identity.replace(element=identity)
        self.request_user_sync(user)

    @staticmethod
    def generate_auth_response(
        request_id: str,
        saml_response_tpl: str,
        asserted_identity: str,
        date_of_birth: Optional[datetime.datetime] = None,
        age: int = 10,
        credentials_used: Optional[List[ElementKey]] = None,
    ) -> bytes:
        """
        Generates a fresh signed authentication response
        """

        timestamp = datetime.datetime.utcnow() - datetime.timedelta(seconds=age)
        tomorrow = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        if date_of_birth is None:
            date_of_birth = datetime.datetime.strptime(asserted_identity[:8], '%Y%m%d')

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
                    'asserted_identity': asserted_identity,
                    'date_of_birth': date_of_birth.strftime('%Y-%m-%d'),
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
        relay_state: str = 'relay_state',
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

    def _setup_faked_login(
        self, session: EduidSession, credentials_used: List[ElementKey], redirect_url: Optional[str] = None
    ) -> None:
        logger.debug(f'Test setting credentials used for login in session {session}: {credentials_used}')
        _authn_id = AuthnRequestRef(str(uuid4()))
        if redirect_url is None:
            redirect_url = self.default_redirect_url
        session.authn.sp.authns[_authn_id] = SP_AuthnRequest(
            post_authn_action=AuthnAcsAction.login,
            credentials_used=credentials_used,
            authn_instant=utc_now(),
            redirect_url=redirect_url,
            frontend_action=FALLBACK_FRONTEND_ACTION,
        )

    def _get_request_id_from_session(self, session: EduidSession) -> Tuple[str, AuthnRequestRef]:
        """extract the (probable) SAML request ID from the session"""
        oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
        ids = oq_cache.outstanding_queries().keys()
        logger.debug(f'Outstanding queries for eidas in session {session}: {ids}')
        if len(ids) != 1:
            raise RuntimeError('More or less than one authn request in the session')
        saml_req_id = list(ids)[0]
        req_ref = AuthnRequestRef(oq_cache.outstanding_queries()[saml_req_id])
        return saml_req_id, req_ref

    def _verify_redirect_url(
        self,
        response: Response,
        expect_msg: TranslatableMsg,
        expect_error: bool,
        expect_redirect_url: Optional[str],
    ) -> None:
        assert response.status_code == 302

        logger.debug(f'Verifying returned location {response.location}')

        ps = urlparse(response.location)
        # Check the base part of the URL (everything except the query string)
        _ps = ps._replace(query='')  # type: ignore
        if expect_redirect_url is not None:
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
        token_verified: bool = False,
        num_proofings: int = 0,
        identity: Optional[IdentityElement] = None,
        locked_identity: Optional[IdentityElement] = None,
        identity_present: bool = True,
        identity_verified: bool = False,
    ):
        """This function is used to verify a user's parameters at the start of a test case,
        and then again at the end to ensure the right set of changes occurred to the user in the database.
        """
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        user_mfa_tokens = user.credentials.filter(FidoCredential)

        # Check token status
        assert len(user_mfa_tokens) == num_mfa_tokens, 'Unexpected number of FidoCredentials on user'
        if user_mfa_tokens:
            assert user_mfa_tokens[0].is_verified == token_verified, 'User token unexpected is_verified'
        assert self.app.proofing_log.db_count() == num_proofings, 'Unexpected number of proofings in db'

        if identity is not None:
            # Check parameters of a specific nin
            user_identity = user.identities.find(identity.identity_type)
            if not identity_present:
                assert (
                    user_identity is None or user_identity.unique_value != identity.unique_value
                ) is True, f'identity {identity} not expected to be present on user'
                return None
            assert user_identity is not None, f'identity {identity} not present on user'
            assert (
                user_identity.unique_value == identity.unique_value
            ), 'user_identity.unique_value != identity.unique_value'
            assert (
                user_identity.is_verified == identity_verified
            ), f'{user_identity} was expected to be verified={identity_verified}'

        if locked_identity is not None:
            # Check parameters of a specific locked nin
            user_locked_identity = user.locked_identity.find(locked_identity.identity_type)
            assert user_locked_identity is not None, f'locked identity {locked_identity} not present'
            assert (
                user_locked_identity.unique_value == locked_identity.unique_value
            ), f'locked identity {user_locked_identity.unique_value} not matching {locked_identity.unique_value}'

    def reauthn(
        self,
        endpoint: str,
        expect_msg: TranslatableMsg,
        expect_mfa_action_error: Optional[MfaActionError] = None,
        eppn: Optional[str] = None,
        age: int = 10,
        identity: Optional[Union[NinIdentity, EIDASIdentity]] = None,
        logged_in: bool = True,
        next_url: Optional[str] = None,
        response_template: Optional[str] = None,
        expect_error: bool = False,
        expect_redirect_url: Optional[str] = None,
        browser: Optional[FlaskClient] = None,
    ) -> None:
        return self._call_endpoint_and_saml_acs(
            endpoint=endpoint,
            eppn=eppn,
            expect_msg=expect_msg,
            expect_mfa_action_error=expect_mfa_action_error,
            expect_error=expect_error,
            expect_redirect_url=expect_redirect_url,
            age=age,
            identity=identity,
            logged_in=logged_in,
            next_url=next_url,
            response_template=response_template,
            browser=browser,
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
        identity: Optional[Union[NinIdentity, EIDASIdentity]] = None,
        response_template: Optional[str] = None,
        credentials_used: Optional[List[ElementKey]] = None,
        verify_credential: Optional[ElementKey] = None,
        browser: Optional[FlaskClient] = None,
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
            identity=identity,
            response_template=response_template,
            credentials_used=credentials_used,
            verify_credential=verify_credential,
            browser=browser,
        )

    def _call_endpoint_and_saml_acs(
        self,
        endpoint: str,
        eppn: Optional[str],
        expect_msg: TranslatableMsg,
        expect_redirect_url: Optional[str] = None,
        expect_mfa_action_error: Optional[MfaActionError] = None,
        expect_error: bool = False,
        expect_saml_error: bool = False,
        age: int = 10,
        identity: Optional[Union[NinIdentity, EIDASIdentity]] = None,
        logged_in: bool = True,
        next_url: Optional[str] = None,
        response_template: Optional[str] = None,
        credentials_used: Optional[List[ElementKey]] = None,
        verify_credential: Optional[ElementKey] = None,
        browser: Optional[FlaskClient] = None,
    ) -> None:

        if eppn is None:
            eppn = self.test_user_eppn

        if identity is None:
            identity = self.test_user_nin

        if response_template is None:
            response_template = self.saml_response_tpl_success

        if next_url is None:
            next_url = self.default_redirect_url

        if browser is None:
            browser = self.browser

        browser_with_session_cookie = self.session_cookie(browser, eppn)
        if not logged_in:
            browser_with_session_cookie = self.session_cookie_anon(browser)

        with browser_with_session_cookie as browser:
            if credentials_used:
                with browser.session_transaction() as sess:  # type: ignore
                    self._setup_faked_login(session=sess, credentials_used=credentials_used)

            if logged_in is False:
                with browser.session_transaction() as sess:  # type: ignore
                    # the user is at least partial logged in at this stage
                    sess.common.eppn = eppn

            _url = f'{endpoint}/?idp={self.test_idp}'
            if next_url is not None:
                _url = f'{_url}&next={quote_plus(bytes(next_url, "utf-8"))}'
            logger.debug(f'Test fetching url: {_url}')
            response = browser.get(_url)  # type: ignore
            logger.debug(f'Test fetched url {_url}, response: {response}')
            assert response.status_code == 302

            with browser.session_transaction() as sess:  # type: ignore
                request_id, authn_ref = self._get_request_id_from_session(sess)

            authn_response = self.generate_auth_response(
                request_id,
                response_template,
                asserted_identity=identity.unique_value,
                date_of_birth=identity.date_of_birth,
                age=age,
                credentials_used=credentials_used,
            )
            if verify_credential:
                logger.debug(
                    f'Test setting verify_token_action_credential_id = {verify_credential} '
                    f'(was: {sess.eidas.verify_token_action_credential_id})'
                )
                with browser.session_transaction() as sess:  # type: ignore
                    sess.eidas.verify_token_action_credential_id = verify_credential

            data = {'SAMLResponse': base64.b64encode(authn_response), 'RelayState': ''}
            response = browser.post('/saml2-acs', data=data)  # type: ignore

            if expect_mfa_action_error is not None:
                with browser.session_transaction() as sess:  # type: ignore
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

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_u2f_token_verify(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
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

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_webauthn_token_verify(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
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

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=1)

    def test_mfa_token_verify_wrong_verified_nin(self):
        eppn = self.test_user.eppn
        nin = self.test_user_wrong_nin
        credential = self.add_token_to_user(eppn, 'test', 'u2f')

        self._verify_user_parameters(eppn, identity=nin, identity_present=False)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            identity=nin,
        )

        self._verify_user_parameters(eppn, identity=nin, identity_present=False)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_token_verify_no_verified_nin(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_user_nin
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn, identity_verified=False)

        self.verify_token(
            endpoint=f'/verify-token/{credential.key}',
            eppn=eppn,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            identity=nin,
        )

        # Verify the user now has a verified NIN
        self._verify_user_parameters(
            eppn, token_verified=True, num_proofings=2, identity_present=True, identity=nin, identity_verified=True
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
            identity=self.test_user_wrong_nin,
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
            identity=self.test_user_wrong_nin,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_webauthn_token_verify_backdoor(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn)

        self.app.conf.magic_cookie = 'magic-cookie'
        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            browser.set_cookie('localhost', key='nin', value=nin.number)
            self.verify_token(
                endpoint=f'/verify-token/{credential.key}',
                eppn=eppn,
                expect_msg=EidasMsg.verify_success,
                credentials_used=[credential.key, 'other_id'],
                verify_credential=credential.key,
                browser=browser,
            )

        self._verify_user_parameters(eppn, identity=nin, identity_verified=True, token_verified=True, num_proofings=2)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_verify_success,
            eppn=eppn,
            expect_redirect_url='http://test.localhost/profile',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify_no_official_address(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        # add empty official address and deregistration information as for a user that has emigrated
        mock_get_all_navet_data.return_value.person.postal_addresses.official_address = OfficialAddress()
        mock_get_all_navet_data.return_value.person.deregistration_information = DeregistrationInformation(
            date='20220509', cause_code=DeregisteredCauseCode.EMIGRATED
        )
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_verify_success,
            eppn=eppn,
            expect_redirect_url='http://test.localhost/profile',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1)
        # check proofing log
        doc = self.app.proofing_log._get_documents_by_attr(attr='eduPersonPrincipalName', value=eppn)[0]
        assert doc['user_postal_address']['official_address'] == {}
        assert doc['deregistration_information']['cause_code'] == 'UV'

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_login(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True)

        self.reauthn(
            '/mfa-authentication',
            expect_msg=EidasMsg.action_completed,
            eppn=eppn,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=0)

    def test_mfa_login_no_nin(self):
        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, token_verified=False)

        self.reauthn(
            '/mfa-authentication',
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            eppn=eppn,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_login_unverified_nin(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn

        # Add locked nin to user
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        locked_nin = NinIdentity(created_by='test', number=self.test_user_nin.number, is_verified=True)
        user.locked_identity.add(locked_nin)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, token_verified=False)

        self.reauthn(
            '/mfa-authentication',
            expect_msg=EidasMsg.action_completed,
            eppn=eppn,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_eid_mfa_login(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        self.set_eidas_for_user(eppn=eppn, identity=self.test_user_eidas, verified=True)
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=self.test_user_eidas, identity_verified=True)

        self.reauthn(
            '/mfa-authentication-foreign-eid',
            expect_msg=EidasMsg.action_completed,
            eppn=eppn,
            identity=self.test_user_eidas,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
            response_template=self.saml_response_foreign_eid_tpl_success,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=self.test_user_eidas, identity_verified=True, num_proofings=0
        )

    def test_foreign_eid_mfa_login_no_identity(self):
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=identity, identity_present=False)

        self.reauthn(
            '/mfa-authentication-foreign-eid',
            expect_msg=EidasMsg.foreign_eid_not_matching,
            expect_error=True,
            eppn=eppn,
            identity=identity,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
            response_template=self.saml_response_foreign_eid_tpl_success,
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_eid_mfa_login_unverified_identity(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas

        # Add locked identity to user
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        identity.is_verified = True
        user.locked_identity.add(identity)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=identity, identity_present=False)

        self.reauthn(
            '/mfa-authentication-foreign-eid',
            expect_msg=EidasMsg.action_completed,
            eppn=eppn,
            identity=identity,
            logged_in=False,
            next_url='http://idp.test.localhost/mfa-step',
            expect_redirect_url='http://idp.test.localhost/mfa-step',
            response_template=self.saml_response_foreign_eid_tpl_success,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=identity, identity_present=True, identity_verified=True, num_proofings=1
        )

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_eid_webauthn_token_verify(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')
        self.set_eidas_for_user(eppn=eppn, identity=self.test_user_eidas, verified=True)

        self._verify_user_parameters(eppn, identity=self.test_user_eidas, identity_verified=True)

        self.verify_token(
            endpoint=f'/verify-token-foreign-eid/{credential.key}',
            eppn=eppn,
            identity=self.test_user_eidas,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            response_template=self.saml_response_foreign_eid_tpl_success,
        )

        self._verify_user_parameters(
            eppn, identity=self.test_user_eidas, identity_verified=True, token_verified=True, num_proofings=1
        )

    def test_foreign_eid_mfa_token_verify_wrong_verified_identity(self):
        eppn = self.test_user.eppn
        identity = self.test_user_other_eidas
        self.set_eidas_for_user(eppn=eppn, identity=identity, verified=True)
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn, identity=identity, identity_present=True, identity_verified=True)

        self.verify_token(
            endpoint=f'/verify-token-foreign-eid/{credential.key}',
            eppn=eppn,
            identity=self.test_user_eidas,
            expect_msg=EidasMsg.foreign_eid_not_matching,
            expect_error=True,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            response_template=self.saml_response_foreign_eid_tpl_success,
        )

        self._verify_user_parameters(
            eppn, identity=identity, identity_present=True, identity_verified=True, num_proofings=0
        )

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_eid_mfa_token_verify_no_verified_identity(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn, identity_verified=False, identity_present=False)

        self.verify_token(
            endpoint=f'/verify-token-foreign-eid/{credential.key}',
            eppn=eppn,
            identity=identity,
            expect_msg=EidasMsg.verify_success,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            response_template=self.saml_response_foreign_eid_tpl_success,
        )

        # Verify the user now has a verified eidas identity
        self._verify_user_parameters(
            eppn, token_verified=True, num_proofings=2, identity_present=True, identity=identity, identity_verified=True
        )

    def test_foreign_eid_mfa_token_verify_no_mfa_login(self):
        eppn = self.test_user.eppn
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn)

        with self.session_cookie(self.browser, eppn) as browser:
            response = browser.get(f'/verify-token-foreign-eid/{credential.key}')
            assert response.status_code == 302
            assert response.location == (
                'http://test.localhost/reauthn?next=' f'http://test.localhost/verify-token/{credential.key}'
            )

        self._verify_user_parameters(eppn)

    def test_foreign_eid_mfa_token_verify_no_mfa_token_in_session(self):
        eppn = self.test_user.eppn
        identity = self.test_user_eidas
        credential = self.add_token_to_user(eppn, 'test', 'webauthn')

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint=f'/verify-token-foreign-eid/{credential.key}',
            eppn=eppn,
            identity=identity,
            expect_msg=EidasMsg.token_not_in_creds,
            credentials_used=[credential.key, 'other_id'],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_login_backdoor(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin

        # add verified magic cookie nin to user
        self.add_nin_to_user(eppn=eppn, nin=nin.number, verified=True)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True)

        self.app.conf.magic_cookie = 'magic-cookie'
        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            browser.set_cookie('localhost', key='nin', value=nin.number)
            self.reauthn(
                '/mfa-authentication',
                expect_msg=EidasMsg.action_completed,
                eppn=eppn,
                logged_in=False,
                next_url='http://idp.test.localhost/mfa-step',
                expect_redirect_url='http://idp.test.localhost/mfa-step',
                browser=browser,
            )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=0)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify_backdoor(self, mock_request_user_sync: Any):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.app.conf.magic_cookie = 'magic-cookie'

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            browser.set_cookie('localhost', key='nin', value=nin.number)
            self.reauthn(
                '/verify-nin',
                expect_msg=EidasMsg.nin_verify_success,
                eppn=eppn,
                expect_redirect_url='http://test.localhost/profile',
                browser=browser,
            )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True, num_proofings=1)

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify_no_backdoor_in_pro(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.app.conf.magic_cookie = 'magic-cookie'
        self.app.conf.environment = EduidEnvironment.production

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            browser.set_cookie('localhost', key='nin', value=nin.number)
            self.reauthn(
                '/verify-nin',
                expect_msg=EidasMsg.nin_verify_success,
                eppn=eppn,
                expect_redirect_url='http://test.localhost/profile',
                browser=browser,
            )

        # the tests checks that the default nin was verified and not the nin set in the test cookie
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, num_mfa_tokens=0, num_proofings=1, identity_verified=True
        )

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_verify_no_backdoor_misconfigured(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.app.conf.magic_cookie = 'magic-cookie'

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value='NOT-the-magic-cookie')
            browser.set_cookie('localhost', key='nin', value=nin.number)
            self.reauthn(
                '/verify-nin',
                expect_msg=EidasMsg.nin_verify_success,
                eppn=eppn,
                expect_redirect_url='http://test.localhost/profile',
                browser=browser,
            )

        # the tests checks that the default nin was verified and not the nin set in the test cookie
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, num_mfa_tokens=0, num_proofings=1, identity_verified=True
        )

    def test_nin_verify_already_verified(self):
        # Verify that the test user has a verified NIN in the database already
        eppn = self.test_user.eppn
        nin = self.test_user_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert user.identities.nin.is_verified is True

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_already_verified,
            expect_error=True,
            expect_redirect_url='http://test.localhost/profile',
            identity=nin,
        )

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_mfa_authentication_verified_user(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert user.identities.nin.is_verified is True, 'User was expected to have a verified NIN'

        assert user.credentials.filter(SwedenConnectCredential) == []
        credentials_before = user.credentials.to_list()

        self.reauthn(
            endpoint='/mfa-authentication',
            expect_msg=EidasMsg.action_completed,
            expect_redirect_url=self.default_redirect_url,
        )

        # Verify that an ExternalCredential was added
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.credentials.to_list()) == len(credentials_before) + 1

        sweconn_creds = user.credentials.filter(SwedenConnectCredential)
        assert len(sweconn_creds) == 1
        cred = sweconn_creds[0]
        assert cred.level == self.app.conf.required_loa[0]

    def test_mfa_authentication_too_old_authn_instant(self):
        self.reauthn(
            endpoint='/mfa-authentication',
            next_url=self.default_redirect_url,
            age=61,
            expect_msg=EidasMsg.reauthn_expired,
            expect_mfa_action_error=MfaActionError.authn_too_old,
            expect_error=True,
            expect_redirect_url=self.default_redirect_url,
        )

    def test_mfa_authentication_wrong_nin(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin.is_verified is True, 'User was expected to have a verified NIN'

        self.reauthn(
            endpoint='/mfa-authentication',
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            identity=self.test_user_wrong_nin,
        )

    @patch('eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_nin_staging_remap_verify(self, mock_request_user_sync, mock_get_all_navet_data):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        remapped_nin = NinIdentity(number='190102031234')
        self.app.conf.environment = EduidEnvironment.staging
        self.app.conf.staging_nin_map = {self.test_user_nin.number: remapped_nin.number}

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity_verified=False, identity=remapped_nin, identity_present=False
        )

        self.reauthn(
            '/verify-nin',
            expect_msg=EidasMsg.nin_verify_success,
            eppn=eppn,
            expect_redirect_url='http://test.localhost/profile',
            identity=self.test_user_nin,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=remapped_nin, identity_verified=True, num_proofings=1
        )

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_identity_verify(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_present=False)

        self.reauthn(
            '/verify-foreign-identity',
            expect_msg=EidasMsg.foreign_eid_verify_success,
            eppn=eppn,
            identity=identity,
            response_template=self.saml_response_foreign_eid_tpl_success,
            expect_redirect_url='http://test.localhost/profile',
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=identity, identity_verified=True, num_proofings=1)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_identity_verify_existing_prid_persistence_A(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_other_eidas
        # Add locked identity with prid persistence A to user
        locked_identity = self.test_user_eidas
        locked_identity.prid_persistence = PridPersistence.A
        locked_identity.is_verified = True
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(locked_identity)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, locked_identity=locked_identity, identity_present=False)

        self.reauthn(
            '/verify-foreign-identity',
            expect_msg=CommonMsg.locked_identity_not_matching,
            expect_error=True,
            eppn=eppn,
            identity=identity,
            response_template=self.saml_response_foreign_eid_tpl_success,
            expect_redirect_url='http://test.localhost/profile',
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, locked_identity=locked_identity, identity_verified=False, num_proofings=0
        )

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_foreign_identity_verify_existing_prid_persistence_B(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_other_eidas
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        # Add locked identity with prid persistence B and same date of birth to user
        locked_identity = EIDASIdentity(
            prid='XA:some_other_other_prid',
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat('1920-11-18'),
            country_code='XX',
            is_verified=True,
        )
        # add same names as assertion to the user
        user.given_name = 'Javier'
        user.surname = 'Garcia'
        user.locked_identity.add(locked_identity)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, locked_identity=locked_identity, identity_present=False)

        self.reauthn(
            '/verify-foreign-identity',
            expect_msg=EidasMsg.foreign_eid_verify_success,
            eppn=eppn,
            identity=identity,
            response_template=self.saml_response_foreign_eid_tpl_success,
            expect_redirect_url='http://test.localhost/profile',
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, locked_identity=identity, identity=identity, identity_verified=True, num_proofings=1
        )


class RedirectWithMsgTests(TestCase):
    def test_redirect_with_message(self):
        url = "https://www.exaple.com/services/eidas/?next=/authn"
        response = redirect_with_msg(url, EidasMsg.authn_context_mismatch)
        self.assertEqual(
            response.location,
            'https://www.exaple.com/services/eidas/?next=%2Fauthn&msg=%3AERROR%3Aeidas.authn_context_mismatch',
        )
