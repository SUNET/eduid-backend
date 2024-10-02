import base64
import datetime
import logging
import os
from collections.abc import Mapping
from typing import Any
from unittest import TestCase
from unittest.mock import MagicMock, patch

from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb import NinIdentity
from eduid.userdb.credentials.external import EidasCredential, ExternalCredential, SwedenConnectCredential
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import EIDASIdentity, EIDASLoa, IdentityProofingMethod, PridPersistence
from eduid.webapp.common.api.messages import AuthnStatusMsg, CommonMsg, TranslatableMsg, redirect_with_msg
from eduid.webapp.common.api.testing import CSRFTestClient
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.testing import ProofingTests
from eduid.webapp.common.session import EduidSession
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest
from eduid.webapp.eidas.app import EidasApp, init_eidas_app
from eduid.webapp.eidas.helpers import EidasMsg

__author__ = "lundberg"

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class EidasTests(ProofingTests[EidasApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, *args: Any, **kwargs: Any) -> None:
        self.test_user_eppn = "hubba-bubba"
        self.test_unverified_user_eppn = "hubba-baar"
        self.test_user_nin = NinIdentity(
            number="197801011234", date_of_birth=datetime.datetime.fromisoformat("1978-01-01")
        )
        self.test_user_eidas = EIDASIdentity(
            prid="XB:1bjrk7depnmhu7xn56kon3mlc9q1s0",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat("1964-12-31"),
            country_code="XB",
        )
        self.test_user_wrong_nin = NinIdentity(
            number="190001021234", date_of_birth=datetime.datetime.fromisoformat("1900-01-02")
        )
        self.test_user_other_eidas = EIDASIdentity(
            prid="XA:some_other_prid",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat("1920-11-18"),
            country_code="XA",
        )
        self.test_backdoor_nin = NinIdentity(
            number="190102031234", date_of_birth=datetime.datetime.fromisoformat("1901-02-03")
        )
        self.test_idp = "https://idp.example.com/simplesaml/saml2/idp/metadata.php"
        self.default_redirect_url = "http://redirect.localhost/redirect"

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
</samlp:Response>"""  # noqa: E501
        self.saml_response_tpl_fail = """<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{sp_url}saml2-acs" ID="_ebad01e547857fa54927b020dba1edb1" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
      <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" />
    </saml2p:StatusCode>
    <saml2p:StatusMessage>User login was not successful or could not meet the requirements of the requesting application.</saml2p:StatusMessage>
  </saml2p:Status>
</saml2p:Response>"""  # noqa: E501
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
</saml2p:Response>"""  # noqa: E501
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
</samlp:Response>"""  # noqa: E501

        super().setUp(users=["hubba-bubba", "hubba-baar"])

    def load_app(self, config: Mapping[str, Any]) -> EidasApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_eidas_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        saml_config = os.path.join(HERE, "saml2_settings.py")
        config.update(
            {
                "saml2_settings_module": saml_config,
                "safe_relay_domain": "localhost",
                "magic_cookie": "",
                "magic_cookie_name": "magic-cookie",
                "magic_cookie_idp": self.test_idp,
                "environment": "dev",
                "freja_idp": self.test_idp,
                "foreign_identity_idp": self.test_idp,
                "frontend_action_authn_parameters": {
                    FrontendAction.LOGIN_MFA_AUTHN.value: {
                        "force_authn": True,
                        "force_mfa": True,
                        "finish_url": "http://test.localhost/testing-mfa-authenticate/{app_name}/{authn_id}",
                    },
                    FrontendAction.VERIFY_IDENTITY.value: {
                        "force_authn": True,
                        "finish_url": "http://test.localhost/testing-verify-identity/{app_name}/{authn_id}",
                    },
                    FrontendAction.VERIFY_CREDENTIAL.value: {
                        "force_authn": True,
                        "force_mfa": True,
                        "allow_login_auth": True,
                        "finish_url": "http://test.localhost/testing-verify-credential/{app_name}/{authn_id}",
                    },
                },
            }
        )
        return config

    def add_nin_to_user(self, eppn: str, nin: str, verified: bool) -> NinIdentity:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinIdentity(number=nin, created_by="test", is_verified=verified)
        user.identities.add(nin_element)
        self.request_user_sync(user)
        return nin_element

    def set_eidas_for_user(self, eppn: str, identity: EIDASIdentity, verified: bool) -> None:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
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
        date_of_birth: datetime.datetime | None = None,
        age: int = 10,
        credentials_used: list[ElementKey] | None = None,
    ) -> bytes:
        """
        Generates a fresh signed authentication response
        """

        timestamp = utc_now() - datetime.timedelta(seconds=age)
        tomorrow = utc_now() + datetime.timedelta(days=1)
        yesterday = utc_now() - datetime.timedelta(days=1)
        if date_of_birth is None:
            date_of_birth = datetime.datetime.strptime(asserted_identity[:8], "%Y%m%d")

        sp_baseurl = "http://test.localhost:6544/"

        extra_attributes: list[str] = []

        if credentials_used:
            for cred in credentials_used:
                this = f"""
                       <saml:Attribute Name="eduidIdPCredentialsUsed"
                                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                           <saml:AttributeValue xsi:type="xs:string">{cred}</saml:AttributeValue>
                       </saml:Attribute>
                       """
                extra_attributes += [this]

        extra_attributes_str = "\n".join(extra_attributes)

        resp = " ".join(
            saml_response_tpl.format(
                **{
                    "asserted_identity": asserted_identity,
                    "date_of_birth": date_of_birth.strftime("%Y-%m-%d"),
                    "session_id": request_id,
                    "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "tomorrow": tomorrow.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "yesterday": yesterday.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "sp_url": sp_baseurl,
                    "extra_attributes": extra_attributes_str,
                }
            ).split()
        )

        return resp.encode("utf-8")

    @staticmethod
    def _setup_faked_login(session: EduidSession, credentials_used: list[ElementKey]) -> None:
        logger.debug(f"Test setting credentials used for login in session {session}: {credentials_used}")
        authn_req = SP_AuthnRequest(
            post_authn_action=AuthnAcsAction.login,
            credentials_used=credentials_used,
            authn_instant=utc_now(),
            frontend_action=FrontendAction.LOGIN,
            finish_url="http://test.localhost/testing-mfa-authenticate/{app_name}/{authn_id}",
        )
        session.authn.sp.authns = {authn_req.authn_id: authn_req}

    @staticmethod
    def _get_request_id_from_session(session: EduidSession) -> tuple[str, AuthnRequestRef]:
        """extract the (probable) SAML request ID from the session"""
        oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
        ids = oq_cache.outstanding_queries().keys()
        logger.debug(f"Outstanding queries for eidas in session {session}: {ids}")
        if len(ids) != 1:
            raise RuntimeError("More or less than one authn request in the session")
        saml_req_id = list(ids)[0]
        req_ref = AuthnRequestRef(oq_cache.outstanding_queries()[saml_req_id])
        return saml_req_id, req_ref

    @staticmethod
    def _verify_finish_url(
        finish_url: str,
        expected_finish_url: str,
    ) -> None:
        logger.debug(f"Verifying returned location {finish_url}")

        # Remove the /{app_name}/{authn_id} part from the finish URL
        finish_url = "/".join(finish_url.split("/")[:-2])
        logger.debug(f"Removed the /app_name/authn_id from the location before checking it: {finish_url}")
        expected_finish_url = "/".join(expected_finish_url.split("/")[:-2])

        assert finish_url == expected_finish_url, f"expected finish url {expected_finish_url} but got {finish_url}"

    def reauthn(
        self,
        endpoint: str,
        expect_msg: TranslatableMsg,
        frontend_action: FrontendAction,
        age: int = 10,
        browser: CSRFTestClient | None = None,
        eppn: str | None = None,
        expect_error: bool = False,
        identity: NinIdentity | EIDASIdentity | None = None,
        logged_in: bool = True,
        method: str = "freja",
        next_url: str | None = None,
        response_template: str | None = None,
    ) -> None:
        return self._call_endpoint_and_saml_acs(
            age=age,
            browser=browser,
            endpoint=endpoint,
            eppn=eppn,
            expect_error=expect_error,
            expect_msg=expect_msg,
            frontend_action=frontend_action,
            identity=identity,
            logged_in=logged_in,
            method=method,
            next_url=next_url,
            response_template=response_template,
        )

    def verify_token(
        self,
        endpoint: str,
        expect_msg: TranslatableMsg,
        frontend_action: FrontendAction,
        age: int = 10,
        browser: CSRFTestClient | None = None,
        credentials_used: list[ElementKey] | None = None,
        eppn: str | None = None,
        expect_error: bool = False,
        expect_saml_error: bool = False,
        identity: NinIdentity | EIDASIdentity | None = None,
        method: str = "freja",
        response_template: str | None = None,
        verify_credential: ElementKey | None = None,
    ) -> None:
        return self._call_endpoint_and_saml_acs(
            age=age,
            browser=browser,
            credentials_used=credentials_used,
            endpoint=endpoint,
            eppn=eppn,
            expect_error=expect_error,
            expect_msg=expect_msg,
            expect_saml_error=expect_saml_error,
            frontend_action=frontend_action,
            identity=identity,
            method=method,
            response_template=response_template,
            verify_credential=verify_credential,
        )

    def _get_authn_redirect_url(
        self,
        browser: CSRFTestClient,
        endpoint: str,
        method: str,
        frontend_action: FrontendAction,
        expect_success: bool = True,
        verify_credential: ElementKey | None = None,
        frontend_state: str | None = None,
    ) -> str:
        with browser.session_transaction() as sess:
            csrf_token = sess.get_csrf_token()
        req = {
            "csrf_token": csrf_token,
            "method": method,
        }
        if frontend_state:
            req["frontend_state"] = frontend_state
        if endpoint == "/verify-credential" and verify_credential:
            req["credential_id"] = verify_credential
        if frontend_action is not None:
            req["frontend_action"] = frontend_action.value
        assert browser
        response = browser.post(endpoint, json=req)
        if expect_success:
            self._check_success_response(response, type_=None, payload={"csrf_token": csrf_token})
            loc = self.get_response_payload(response).get("location")
            assert loc is not None
        else:
            loc = None
            payload = {"csrf_token": csrf_token}
            if verify_credential:
                payload["credential_description"] = "test"
            self._check_error_response(response, type_=None, payload=payload, msg=AuthnStatusMsg.must_authenticate)
        return loc

    def _call_endpoint_and_saml_acs(
        self,
        endpoint: str,
        method: str,
        eppn: str | None,
        expect_msg: TranslatableMsg,
        frontend_action: FrontendAction,
        age: int = 10,
        browser: CSRFTestClient | None = None,
        credentials_used: list[ElementKey] | None = None,
        expect_error: bool = False,
        expect_saml_error: bool = False,
        identity: NinIdentity | EIDASIdentity | None = None,
        logged_in: bool = True,
        next_url: str | None = None,
        response_template: str | None = None,
        verify_credential: ElementKey | None = None,
        frontend_state: str | None = "This is a unit test",
    ) -> None:
        if eppn is None:
            eppn = self.test_user_eppn

        if identity is None:
            identity = self.test_user_nin

        if response_template is None:
            response_template = self.saml_response_tpl_success

        if browser is None:
            browser = self.browser

        expected_finish_url = self.app.conf.frontend_action_authn_parameters[frontend_action].finish_url

        assert isinstance(browser, CSRFTestClient)

        browser_with_session_cookie = self.session_cookie(browser, eppn)
        if not logged_in:
            browser_with_session_cookie = self.session_cookie_anon(browser)

        with browser_with_session_cookie as browser:
            if credentials_used:
                with browser.session_transaction() as sess:
                    self._setup_faked_login(session=sess, credentials_used=credentials_used)

            if logged_in is False:
                with browser.session_transaction() as sess:
                    # the user is at least partially logged in at this stage
                    sess.common.eppn = eppn

            _url = self._get_authn_redirect_url(
                browser=browser,
                endpoint=endpoint,
                method=method,
                frontend_action=frontend_action,
                verify_credential=verify_credential,
                frontend_state=frontend_state,
            )

            logger.debug(f"Backend told us to proceed with URL {_url}")

            with browser.session_transaction() as sess:
                request_id, authn_ref = self._get_request_id_from_session(sess)

            authn_response = self.generate_auth_response(
                request_id,
                response_template,
                asserted_identity=identity.unique_value,
                date_of_birth=identity.date_of_birth,
                age=age,
                credentials_used=credentials_used,
            )

            data = {"SAMLResponse": base64.b64encode(authn_response), "RelayState": ""}
            logger.debug(f"Posting a fake SAML assertion in response to request {request_id} (ref {authn_ref})")
            response = browser.post("/saml2-acs", data=data)

            if expect_saml_error:
                assert response.status_code == 400
                return

            assert response.status_code == 302

            self._verify_finish_url(
                expected_finish_url=expected_finish_url,
                finish_url=response.location,
            )

            self._verify_status(
                browser=browser,
                expect_msg=expect_msg,
                expect_error=expect_error,
                finish_url=response.location,
                frontend_action=frontend_action,
                frontend_state=frontend_state,
                method=method,
            )

    def test_authenticate(self) -> None:
        response = self.browser.get("/")
        self.assertEqual(response.status_code, 401)
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_EIDAS_SUCCESS")

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_credential(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0)

        for security_key_type in ["u2f", "webauthn"]:
            credential = self.add_security_key_to_user(
                eppn, keyhandle=f"test_{security_key_type}", token_type=security_key_type
            )
            self.verify_token(
                endpoint="/verify-credential",
                eppn=eppn,
                identity=self.test_user.identities.nin,
                expect_msg=EidasMsg.credential_verify_success,
                credentials_used=[credential.key, ElementKey("other_id")],
                verify_credential=credential.key,
                response_template=self.saml_response_tpl_success,
                method="freja",
                frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            )

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=2, num_mfa_tokens=2)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_webauthn_token_verify(self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn

        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=self.test_user.identities.nin,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_success,
            method="freja",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=1)

    def test_mfa_token_verify_wrong_verified_nin(self) -> None:
        eppn = self.test_user.eppn
        nin = self.test_user_wrong_nin
        credential = self.add_security_key_to_user(eppn, "test", "u2f")

        self._verify_user_parameters(eppn, identity=nin, identity_present=False)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=nin,
        )

        self._verify_user_parameters(eppn, identity=nin, identity_present=False)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_mfa_token_verify_no_verified_nin(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_user_nin
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn, identity_verified=False)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=nin,
        )

        # Verify the user now has a verified NIN
        self._verify_user_parameters(
            eppn, token_verified=True, num_proofings=2, identity_present=True, identity=nin, identity_verified=True
        )

    def test_mfa_token_verify_no_mfa_login(self) -> None:
        eppn = self.test_user.eppn
        cred = self.add_security_key_to_user(eppn, "test", "u2f")

        self._verify_user_parameters(eppn)

        with self.session_cookie(self.browser, eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {
                "csrf_token": csrf_token,
                "credential_id": cred.key,
                "method": "freja",
                "frontend_action": FrontendAction.VERIFY_CREDENTIAL.value,
            }
            response = browser.post("/verify-credential", json=data)
            assert response.status_code == 200
            self._check_error_response(
                response=response,
                payload={"credential_description": "test"},
                msg=AuthnStatusMsg.must_authenticate,
                type_="POST_EIDAS_VERIFY_CREDENTIAL_FAIL",
            )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_no_mfa_token_in_session(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            expect_msg=EidasMsg.credential_not_found,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_aborted_auth(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "u2f")

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_cancel_auth(self) -> None:
        eppn = self.test_user.eppn

        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=self.test_user_wrong_nin,
            response_template=self.saml_response_tpl_cancel,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    def test_mfa_token_verify_auth_fail(self) -> None:
        eppn = self.test_user.eppn

        credential = self.add_security_key_to_user(eppn, "test", "u2f")

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=self.test_user_wrong_nin,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
        )

        self._verify_user_parameters(eppn)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_webauthn_token_verify_backdoor(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn)

        self.app.conf.magic_cookie = "magic-cookie"
        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            browser.set_cookie(domain=self.test_domain, key="nin", value=nin.number)
            self.verify_token(
                endpoint="/verify-credential",
                eppn=eppn,
                frontend_action=FrontendAction.VERIFY_CREDENTIAL,
                expect_msg=EidasMsg.credential_verify_success,
                credentials_used=[credential.key, ElementKey("other_id")],
                verify_credential=credential.key,
                browser=browser,
            )

        self._verify_user_parameters(eppn, identity=nin, identity_verified=True, token_verified=True, num_proofings=2)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_nin_verify(self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            expect_msg=EidasMsg.identity_verify_success,
            eppn=eppn,
        )
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn,
            num_mfa_tokens=0,
            identity_verified=True,
            num_proofings=1,
            locked_identity=user.identities.nin,
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
            proofing_version=self.app.conf.freja_proofing_version,
        )
        # check names
        assert user.given_name == "Ûlla"
        assert user.surname == "Älm"
        # check proofing log
        doc = self.app.proofing_log._get_documents_by_attr(attr="eduPersonPrincipalName", value=eppn)[0]
        assert doc["given_name"] == "Ûlla"
        assert doc["surname"] == "Älm"

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_mfa_login(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True)

        self.reauthn(
            "/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            expect_msg=EidasMsg.mfa_authn_success,
            eppn=eppn,
            logged_in=False,
            next_url="http://idp.test.localhost/mfa-step",
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=0)

    def test_mfa_login_no_nin(self) -> None:
        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, token_verified=False)

        self.reauthn(
            "/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            eppn=eppn,
            logged_in=False,
            next_url="http://idp.test.localhost/mfa-step",
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_mfa_login_unverified_nin(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn

        # Add locked nin to user
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        locked_nin = NinIdentity(created_by="test", number=self.test_user_nin.number, is_verified=True)
        user.locked_identity.add(locked_nin)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, token_verified=False)

        self.reauthn(
            "/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            expect_msg=EidasMsg.mfa_authn_success,
            eppn=eppn,
            logged_in=False,
            next_url="http://idp.test.localhost/mfa-step",
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1, locked_identity=user.identities.nin
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_eid_mfa_login(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        self.set_eidas_for_user(eppn=eppn, identity=self.test_user_eidas, verified=True)
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=self.test_user_eidas, identity_verified=True)

        user = self.app.central_userdb.get_user_by_eppn(eppn)

        assert user.credentials.filter(ExternalCredential) == []
        credentials_before = user.credentials.to_list()

        self.reauthn(
            "/mfa-authenticate",
            expect_msg=EidasMsg.mfa_authn_success,
            eppn=eppn,
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            identity=self.test_user_eidas,
            logged_in=False,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=self.test_user_eidas, identity_verified=True, num_proofings=0
        )

        # Verify that an EidasCredential was added
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.credentials.to_list()) == len(credentials_before) + 1

        eidas_creds = user.credentials.filter(EidasCredential)
        assert len(eidas_creds) == 1
        cred = eidas_creds[0]
        assert cred.level in self.app.conf.foreign_required_loa

    def test_foreign_eid_mfa_login_no_identity(self) -> None:
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=identity, identity_present=False)

        self.reauthn(
            "/mfa-authenticate",
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            eppn=eppn,
            identity=identity,
            logged_in=False,
            next_url="http://idp.test.localhost/mfa-step",
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_eid_mfa_login_unverified_identity(self, mock_request_user_sync: MagicMock) -> None:
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
            "/mfa-authenticate",
            expect_msg=EidasMsg.mfa_authn_success,
            eppn=eppn,
            identity=identity,
            logged_in=False,
            next_url="http://idp.test.localhost/mfa-step",
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=identity, identity_present=True, identity_verified=True, num_proofings=1
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_eid_webauthn_token_verify(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        self.set_eidas_for_user(eppn=eppn, identity=self.test_user_eidas, verified=True)

        self._verify_user_parameters(eppn, identity=self.test_user_eidas, identity_verified=True)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=self.test_user_eidas,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, identity=self.test_user_eidas, identity_verified=True, token_verified=True, num_proofings=1
        )

    def test_foreign_eid_mfa_token_verify_wrong_verified_identity(self) -> None:
        eppn = self.test_user.eppn
        identity = self.test_user_other_eidas
        self.set_eidas_for_user(eppn=eppn, identity=identity, verified=True)
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn, identity=identity, identity_present=True, identity_verified=True)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=self.test_user_eidas,
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, identity=identity, identity_present=True, identity_verified=True, num_proofings=0
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_eid_mfa_token_verify_no_verified_identity(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn, identity_verified=False, identity_present=False)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=identity,
            expect_msg=EidasMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        # Verify the user now has a verified eidas identity
        self._verify_user_parameters(
            eppn, token_verified=True, num_proofings=2, identity_present=True, identity=identity, identity_verified=True
        )

    def test_foreign_eid_mfa_token_verify_no_mfa_login(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn)

        with self.session_cookie(self.browser, eppn) as browser:
            location = self._get_authn_redirect_url(
                browser=browser,
                endpoint="/verify-credential",
                method="eidas",
                frontend_action=FrontendAction.VERIFY_CREDENTIAL,
                verify_credential=credential.key,
                expect_success=False,
            )
            assert location is None

        self._verify_user_parameters(eppn)

    def test_foreign_eid_mfa_token_verify_no_mfa_token_in_session(self) -> None:
        eppn = self.test_user.eppn
        identity = self.test_user_eidas
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=identity,
            expect_msg=EidasMsg.credential_not_found,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            response_template=self.saml_response_tpl_fail,
            expect_saml_error=True,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(eppn)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_mfa_login_backdoor(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin

        # add verified magic cookie nin to user
        self.add_nin_to_user(eppn=eppn, nin=nin.number, verified=True)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True)

        self.app.conf.magic_cookie = "magic-cookie"

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie(domain="test.localhost", key="magic-cookie", value=self.app.conf.magic_cookie)
            browser.set_cookie(domain="test.localhost", key="nin", value=nin.number)
            self.reauthn(
                "/mfa-authenticate",
                frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
                expect_msg=EidasMsg.mfa_authn_success,
                eppn=eppn,
                logged_in=False,
                next_url="http://idp.test.localhost/mfa-step",
                browser=browser,
            )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=0)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_nin_verify_backdoor(self, mock_request_user_sync: Any) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.app.conf.magic_cookie = "magic-cookie"

        with self.session_cookie_and_magic_cookie(self.browser, eppn) as browser:
            browser.set_cookie(domain="test.localhost", key="nin", value=nin.number)
            self.reauthn(
                "/verify-identity",
                frontend_action=FrontendAction.VERIFY_IDENTITY,
                expect_msg=EidasMsg.identity_verify_success,
                eppn=eppn,
                browser=browser,
            )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True, num_proofings=1)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_nin_verify_no_backdoor_in_pro(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.environment = EduidEnvironment.production

        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            browser.set_cookie(domain=self.test_domain, key="nin", value=nin.number)
            self.reauthn(
                "/verify-identity",
                frontend_action=FrontendAction.VERIFY_IDENTITY,
                expect_msg=EidasMsg.identity_verify_success,
                eppn=eppn,
                browser=browser,
            )

        # the tests checks that the default nin was verified and not the nin set in the test cookie
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, num_mfa_tokens=0, num_proofings=1, identity_verified=True
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_nin_verify_no_backdoor_misconfigured(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.app.conf.magic_cookie = "magic-cookie"

        with self.session_cookie_and_magic_cookie(
            self.browser, eppn=eppn, magic_cookie_value="NOT-the-magic-cookie"
        ) as browser:
            browser.set_cookie(domain="test.localhost", key="nin", value=nin.number)
            self.reauthn(
                "/verify-identity",
                frontend_action=FrontendAction.VERIFY_IDENTITY,
                expect_msg=EidasMsg.identity_verify_success,
                eppn=eppn,
                browser=browser,
            )

        # the tests checks that the default nin was verified and not the nin set in the test cookie
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, num_mfa_tokens=0, num_proofings=1, identity_verified=True
        )

    def test_nin_verify_already_verified(self) -> None:
        # Verify that the test user has a verified NIN in the database already
        eppn = self.test_user.eppn
        nin = self.test_user_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            expect_msg=ProofingMsg.identity_already_verified,
            expect_error=True,
            identity=nin,
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_mfa_authentication_verified_user(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True, "User was expected to have a verified NIN"

        assert user.credentials.filter(SwedenConnectCredential) == []
        credentials_before = user.credentials.to_list()

        self.reauthn(
            endpoint="/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            expect_msg=EidasMsg.mfa_authn_success,
        )

        # Verify that an ExternalCredential was added
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.credentials.to_list()) == len(credentials_before) + 1

        sweconn_creds = user.credentials.filter(SwedenConnectCredential)
        assert len(sweconn_creds) == 1
        cred = sweconn_creds[0]
        assert cred.level in self.app.conf.required_loa

    def test_mfa_authentication_too_old_authn_instant(self) -> None:
        self.reauthn(
            endpoint="/mfa-authenticate",
            next_url=self.default_redirect_url,
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            age=61,
            expect_msg=EidasMsg.authn_instant_too_old,
            expect_error=True,
        )

    def test_mfa_authentication_wrong_nin(self) -> None:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True, "User was expected to have a verified NIN"

        self.reauthn(
            endpoint="/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            expect_msg=EidasMsg.identity_not_matching,
            expect_error=True,
            identity=self.test_user_wrong_nin,
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_nin_staging_remap_verify(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        remapped_nin = NinIdentity(number="190102031234")
        self.app.conf.environment = EduidEnvironment.staging
        self.app.conf.nin_attribute_map = {self.test_user_nin.number: remapped_nin.number}

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity_verified=False, identity=remapped_nin, identity_present=False
        )

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            expect_msg=EidasMsg.identity_verify_success,
            eppn=eppn,
            identity=self.test_user_nin,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=remapped_nin, identity_verified=True, num_proofings=1
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_identity_verify(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_present=False)

        self.reauthn(
            "/verify-identity",
            expect_msg=EidasMsg.identity_verify_success,
            eppn=eppn,
            identity=identity,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn=eppn)
        self._verify_user_parameters(
            eppn,
            num_mfa_tokens=0,
            identity=identity,
            identity_verified=True,
            num_proofings=1,
            locked_identity=user.identities.eidas,
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
            proofing_version=self.app.conf.foreign_eid_proofing_version,
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_identity_verify_existing_prid_persistence_A(self, mock_request_user_sync: MagicMock) -> None:
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
            "/verify-identity",
            expect_msg=CommonMsg.locked_identity_not_matching,
            expect_error=True,
            eppn=eppn,
            identity=identity,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, locked_identity=locked_identity, identity_verified=False, num_proofings=0
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_foreign_identity_verify_existing_prid_persistence_B(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_unverified_user_eppn
        identity = self.test_user_other_eidas
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        # Add locked identity with prid persistence B and same date of birth to user
        locked_identity = EIDASIdentity(
            prid="XA:some_other_other_prid",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat("1920-11-18"),
            country_code="XX",
            is_verified=True,
        )
        # add same names as assertion to the user
        user.given_name = "Javier"
        user.surname = "Garcia"
        user.locked_identity.add(locked_identity)
        self.app.central_userdb.save(user)

        self._verify_user_parameters(eppn, num_mfa_tokens=0, locked_identity=locked_identity, identity_present=False)

        self.reauthn(
            "/verify-identity",
            expect_msg=EidasMsg.identity_verify_success,
            eppn=eppn,
            identity=identity,
            response_template=self.saml_response_foreign_eid_tpl_success,
            method="eidas",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, locked_identity=identity, identity=identity, identity_verified=True, num_proofings=1
        )


class RedirectWithMsgTests(TestCase):
    def test_redirect_with_message(self) -> None:
        url = "https://www.exaple.com/services/eidas/?next=/authn"
        response = redirect_with_msg(url, EidasMsg.authn_context_mismatch)
        self.assertEqual(
            response.location,
            "https://www.exaple.com/services/eidas/?next=%2Fauthn&msg=%3AERROR%3Aeidas.authn_context_mismatch",
        )
