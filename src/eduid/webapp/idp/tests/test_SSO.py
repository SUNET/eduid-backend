#!/usr/bin/python

import logging
from collections.abc import Mapping
from datetime import datetime
from uuid import uuid4

import saml2.server
import saml2.time_util
from saml2 import BINDING_HTTP_POST

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb.credentials import U2F, Credential, CredentialProofingMethod, Password
from eduid.userdb.identity import (
    EIDASIdentity,
    EIDASLoa,
    FrejaIdentity,
    FrejaRegistrationLevel,
    IdentityList,
    IdentityProofingMethod,
    IdentityType,
    NinIdentity,
    PridPersistence,
)
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import ExternalMfaData
from eduid.webapp.common.session.namespaces import IdP_SAMLPendingRequest, RequestRef
from eduid.webapp.idp.assurance_data import SwamidAssurance
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData, ExternalAuthnData
from eduid.webapp.idp.idp_saml import IdP_SAMLRequest, ServiceInfo
from eduid.webapp.idp.login import NextResult, login_next_step
from eduid.webapp.idp.login_context import LoginContext, LoginContextSAML
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tests.test_api import IdPAPITests
from eduid.webapp.idp.util import b64encode

_U2F = U2F(version="U2F_V2", app_id="unit test", keyhandle="firstU2FElement", public_key="foo")

_U2F_SWAMID_AL3 = U2F(
    version="U2F_V2",
    app_id="unit test",
    keyhandle="U2F SWAMID AL3",
    public_key="foo",
    is_verified=True,
    proofing_method=CredentialProofingMethod.SWAMID_AL3_MFA,
    proofing_version="testing",
)

logger = logging.getLogger(__name__)


def make_SAML_request(class_ref: EduidAuthnContextClass | str | None = None) -> str:
    if isinstance(class_ref, EduidAuthnContextClass):
        class_ref = class_ref.value
    if class_ref is not None:
        authn_context = f"""
  <ns0:RequestedAuthnContext>
    <ns1:AuthnContextClassRef>{class_ref}</ns1:AuthnContextClassRef>
  </ns0:RequestedAuthnContext>
    """
    else:
        authn_context = ""
    xml = f"""
<?xml version="1.0" encoding="UTF-8"?>
<ns0:AuthnRequest xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"
        AssertionConsumerServiceURL="https://sp.example.edu/saml2/acs/"
        Destination="https://unittest-idp.example.edu/sso/post"
        ID="id-57beb2b2f788ec50b10541dbe48e9626"
        IssueInstant="{saml2.time_util.instant()}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Version="2.0">
  <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://sp.example.edu/saml2/metadata/</ns1:Issuer>
  <ns0:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
  {authn_context}
</ns0:AuthnRequest>
        """
    return _transport_encode(xml)


def _transport_encode(data: str) -> str:
    # encode('base64') only works for POST bindings, redirect uses zlib compression too.
    return b64encode("".join(data.split("\n")))


class SAMLError(BaseException):
    pass


class SSOIdPTests(IdPAPITests):
    def _make_login_ticket(
        self,
        req_class_ref: EduidAuthnContextClass | str | None = None,
        request_ref: RequestRef | None = None,
    ) -> LoginContext:
        xmlstr = make_SAML_request(class_ref=req_class_ref)
        binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        if request_ref is None:
            request_ref = RequestRef(str(uuid4()))
        from eduid.webapp.common.session import session

        try:
            saml_data = IdP_SAMLPendingRequest(request=xmlstr, binding=binding, relay_state=None)
            session.idp.pending_requests[request_ref] = saml_data
        except RuntimeError:
            # Ignore RuntimeError: Working outside of request context when not running
            # inside self.app.test_request_context.
            pass
        ticket = LoginContextSAML(request_ref=request_ref)
        return ticket

    def _parse_SAMLRequest(
        self,
        info: Mapping,
        binding: str,
        idp: saml2.server.Server,
        debug: bool = False,
        verify_request_signatures: bool = True,
    ) -> IdP_SAMLRequest:
        """
        Parse a SAMLRequest query parameter (base64 encoded) into an AuthnRequest
        instance.

        If the SAMLRequest is signed, the signature is validated and a BadRequest()
        returned on failure.

        :param info: dict with keys 'SAMLRequest' and possibly 'SigAlg' and 'Signature'
        :param binding: SAML binding
        :returns: pysaml2 interface class IdP_SAMLRequest
        :raise: BadRequest if request signature validation fails
        """
        try:
            saml_req = IdP_SAMLRequest(info["SAMLRequest"], binding, idp, debug=debug)
        except Exception:
            raise SAMLError("No valid SAMLRequest found")

        if "SigAlg" in info and "Signature" in info:  # Signed request
            if verify_request_signatures:
                if not saml_req.verify_signature(info["SigAlg"], info["Signature"]):
                    raise SAMLError("SAML request signature verification failure")
            else:
                logger.debug("Ignoring existing request signature, verify_request_signature is False")
        else:
            # XXX check if metadata says request should be signed ???
            # Leif says requests are typically not signed, and that verifying signatures
            # on SAML requests is considered a possible DoS attack vector, so it is typically
            # not done.
            # XXX implement configuration flag to disable signature verification
            logger.debug("No signature in SAMLRequest")

        return saml_req


class TestSSO(SSOIdPTests):
    def get_user_set_identity(
        self,
        eppn: str,
        identity_type: IdentityType = IdentityType.NIN,
        unique_value: str | None = None,
        eidas_loa: EIDASLoa | None = None,
        freja_registration_level: FrejaRegistrationLevel | None = None,
        proofing_method: IdentityProofingMethod | None = None,
        identity_verified_by: str = "unittest",
        replace_existing_identities: bool = True,
        always_use_security_key: bool = True,
    ) -> IdPUser:
        """
        Get a user from the userdb, and set an identity on it.
        """
        user = self.app.userdb.lookup_user(eppn)
        assert user is not None
        if replace_existing_identities:
            user.identities = IdentityList()
        if unique_value:
            identity: NinIdentity | EIDASIdentity | FrejaIdentity
            match identity_type:
                case IdentityType.NIN:
                    identity = NinIdentity(
                        number=unique_value,
                        created_by="unittest",
                        created_ts=utc_now(),
                        verified_by=identity_verified_by,
                        is_verified=True,
                        proofing_method=proofing_method,
                    )
                case IdentityType.EIDAS:
                    if eidas_loa is None:
                        raise ValueError("eidas_loa must be set")
                    identity = EIDASIdentity(
                        prid=unique_value,
                        prid_persistence=PridPersistence.B,
                        loa=eidas_loa,
                        country_code="DK",
                        date_of_birth=datetime(year=1980, month=1, day=1),
                        created_by="unittest",
                        created_ts=utc_now(),
                        verified_by="unittest",
                        is_verified=True,
                        proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
                    )
                case IdentityType.FREJA:
                    if freja_registration_level is None:
                        raise ValueError("freja_registration_level must be set")
                    identity = FrejaIdentity(
                        user_id=unique_value,
                        registration_level=freja_registration_level,
                        personal_identity_number="test_freja_personal_identity_number",
                        country_code="DK",
                        date_of_birth=datetime(year=1980, month=1, day=1),
                        created_by="unittest",
                        created_ts=utc_now(),
                        verified_by="unittest",
                        is_verified=True,
                        proofing_method=IdentityProofingMethod.FREJA_EID,
                    )
                case _:
                    raise ValueError(f"Unknown identity type {identity_type}")
            user.identities.add(identity)

        # ser user preference always use security key
        user.preferences.always_use_security_key = always_use_security_key

        self.request_user_sync(user)
        self.app.userdb.lookup_user(eppn)
        assert user is not None  # please mypy
        return user

    # ------------------------------------------------------------------------

    def _get_login_response_authn(
        self,
        req_class_ref: EduidAuthnContextClass | str | None,
        credentials: list[str | Credential | AuthnData],
        user: IdPUser | None = None,
        add_tou: bool = True,
        add_credentials_to_this_request: bool = True,  # True = full auth flow, False = only SSO
    ) -> NextResult:
        if user is None:
            # used only to get user
            user = self.get_user_set_identity(
                self.test_user.eppn,
                identity_type=IdentityType.NIN,
            )
        # load user from central db to not get out of sync
        user = self.app.userdb.lookup_user(user.eppn)
        assert user is not None

        if add_tou:
            user, _ = self.add_test_user_tou(eppn=user.eppn)
            assert user is not None

        sso_session_1 = SSOSession(
            authn_request_id="some-unique-id-1",
            authn_credentials=[],
            eppn=user.eppn,
        )
        if "u2f" in credentials and not user.credentials.filter(U2F):
            # add a U2F credential to the user
            user.credentials.add(_U2F)
        for this in credentials:
            if isinstance(this, AuthnData):
                sso_session_1.add_authn_credential(this)
                continue
            if isinstance(this, ExternalMfaData):
                sso_session_1.external_mfa = this
                continue

            # Handle credentials
            _cred: Credential
            if this == "pw":
                _cred = user.credentials.filter(Password)[0]
            elif this == "u2f":
                _cred = user.credentials.filter(U2F)[0]
            elif isinstance(this, Credential):
                _cred = this
            else:
                raise ValueError(f"Unhandled test data: {repr(this)}")

            data = AuthnData(cred_id=_cred.key)
            sso_session_1.add_authn_credential(data)

        # Need to save any changed credentials to the user
        self.request_user_sync(user)
        user = self.app.userdb.lookup_user(user.eppn)
        assert user is not None

        with self.app.test_request_context():
            ticket = self._make_login_ticket(req_class_ref)

            if add_credentials_to_this_request:
                for authn_data in sso_session_1.authn_credentials:
                    credential = user.credentials.find(authn_data.cred_id)
                    assert credential
                    session.idp.log_credential_used(
                        request_ref=ticket.request_ref, credential=credential, authn_data=authn_data
                    )

            # 'prime' the ticket and session for checking later - accessing request_ref gets the SAML data loaded
            # from the session into the ticket.
            assert ticket.request_ref in session.idp.pending_requests

            return login_next_step(ticket, sso_session_1)

    @staticmethod
    def _check_login_response_authn(
        authn_result: NextResult,
        message: IdPMsg,
        expect_success: bool = True,
        accr: EduidAuthnContextClass | None = None,
        assurance_profile: list[SwamidAssurance] | None = None,
        expect_error: bool | None = False,
    ) -> None:
        assert authn_result.message == message, f"Message: {authn_result.message}, Expected: {message}"
        if expect_success:
            assert authn_result.authn_info
            assert authn_result.authn_info.class_ref == accr, (
                f"class_ref: {authn_result.authn_info.class_ref}, Expected: {accr}"
            )
            if assurance_profile is not None:
                assert authn_result.authn_info.authn_attributes["eduPersonAssurance"] == [
                    item.value for item in assurance_profile
                ], "assurance profile does not match"
        else:
            assert authn_result.authn_info is None, f"authn_info: {authn_result.authn_info}, Expected: None"
            assert authn_result.error is expect_error, f"error: {authn_result.error}, Expected: {expect_error}"

    # ------------------------------------------------------------------------

    def test_get_login_response_1(self) -> None:
        """
        Test login with password and SWAMID AL3 U2F, request REFEDS MFA.

        Expect the response Authn to be REFEDS MFA, and assurance attribute to include SWAMID AL3.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        self.add_test_user_security_key(credential=_U2F_SWAMID_AL3)
        user = self.app.userdb.get_user_by_eppn(self.test_user.eppn)
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", _U2F_SWAMID_AL3],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_response_2(self) -> None:
        """
        Test login with password and U2F, request REFEDS MFA.

        Expect the response Authn to be REFEDS MFA.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        self.add_test_user_security_key(credential=_U2F)
        user = self.app.userdb.get_user_by_eppn(self.test_user.eppn)
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", _U2F],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_2,
        )

    def test_get_login_response_external_multifactor(self) -> None:
        """
        Test login with password and external MFA, request REFEDS MFA.

        Expect the response Authn to be REFEDS MFA and assurance attribute to include SWAMID AL3.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        cred = self.add_test_user_external_mfa_cred(user)
        authn = AuthnData(
            cred_id=cred.key,
            timestamp=utc_now(),
            external=ExternalAuthnData(
                issuer="issuer.example.com", authn_context="http://id.elegnamnden.se/loa/1.0/loa3"
            ),
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", authn],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_response_3(self) -> None:
        """
        Test login with password and U2F, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.REFEDS_SFA,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_SFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_4(self) -> None:
        """
        Test login with password, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.REFEDS_SFA,
            credentials=["pw"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_SFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_UNSPECIFIED2(self) -> None:
        """
        Test login with U2F, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.REFEDS_SFA,
            credentials=["u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_SFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_5(self) -> None:
        """
        Test login with password and U2F, request FIDO U2F.

        Expect the response Authn to be FIDO U2F.
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.FIDO_U2F,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.FIDO_U2F,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_6(self) -> None:
        """
        Test login with password and U2F, request plain password-protected-transport.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.PASSWORD_PT,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.PASSWORD_PT,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_7(self) -> None:
        """
        Test login with password, request plain password-protected-transport.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.PASSWORD_PT,
            credentials=["pw"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.PASSWORD_PT,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_8(self) -> None:
        """
        Test login with mfa, request unknown context class.

        Expect an error response.
        """
        out = self._get_login_response_authn(
            req_class_ref="urn:no-such-class",
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out, message=IdPMsg.assurance_failure, expect_success=False, expect_error=True
        )

    def test_get_login_response_9(self) -> None:
        """
        Test login with password, request unknown context class.

        Expect the response Authn to be SAML error response.
        """
        out = self._get_login_response_authn(
            req_class_ref="urn:no-such-class",
            credentials=["pw"],
        )
        self._check_login_response_authn(
            authn_result=out, message=IdPMsg.assurance_failure, expect_success=False, expect_error=True
        )

    def test_get_login_response_10(self) -> None:
        """
        Test login with password, request no authn context class.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(
            req_class_ref=None,
            credentials=["pw"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.PASSWORD_PT,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_11(self) -> None:
        """
        Test login with mfa, request no authn context class.

        Expect the response Authn to be REFEDS_MFA.
        """
        out = self._get_login_response_authn(
            req_class_ref=None,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_assurance_AL1(self) -> None:
        """
        Make sure eduPersonAssurace is SWAMID AL1 with no verified nin.
        """
        out = self._get_login_response_authn(
            req_class_ref=None,
            credentials=["pw"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.PASSWORD_PT,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_assurance_AL2(self) -> None:
        """
        Make sure eduPersonAssurace is SWAMID AL2 with a verified nin.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        out = self._get_login_response_authn(
            req_class_ref=None,
            user=user,
            credentials=["pw"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.PASSWORD_PT,
            assurance_profile=self.app.conf.swamid_assurance_profile_2,
        )

    def test_get_login_eduid_mfa_fido_al1(self) -> None:
        """
        Test login with password and fido for not verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.EDUID_MFA,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.EDUID_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_refeds_mfa_fido_al1(self) -> None:
        """
        Test login with password and fido for not verified user, request REFEDS_MFA.

        Expect the response Authn to be REFEDS_MFA, eduPersonAssurance AL1
        """
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_eduid_mfa_fido_al2(self) -> None:
        """
        Test login with password and fido for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1,Al2
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.EDUID_MFA,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.EDUID_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_2,
        )

    def test_get_login_refeds_mfa_fido_al2(self) -> None:
        """
        Test login with password and fido for verified user, request EDUID_MFA.

        Expect the response Authn to be REFEDS_MFA, eduPersonAssurance AL1,Al2
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_2,
        )

    def test_get_login_eduid_mfa_fido_swamid_al3(self) -> None:
        """
        Test login with password and fido_swamid_al3 for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1,Al2
        """
        self.get_user_set_identity(self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234")
        self.add_test_user_security_key(credential=_U2F_SWAMID_AL3)
        user = self.app.userdb.get_user_by_eppn(self.test_user.eppn)
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.EDUID_MFA,
            credentials=["pw", _U2F_SWAMID_AL3],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.EDUID_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_refeds_mfa_fido_swamid_al3(self) -> None:
        """
        Test login with password and fido_swamid_al3 for verified user, request REFEDS_MFA.

        Expect the response Authn to be REFEDS_MFA, eduPersonAssurance AL1,Al2,Al3
        """
        self.get_user_set_identity(self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234")
        self.add_test_user_security_key(credential=_U2F_SWAMID_AL3)
        user = self.app.userdb.get_user_by_eppn(self.test_user.eppn)
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", _U2F_SWAMID_AL3],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_eduid_mfa_external_mfa_al3(self) -> None:
        """
        Test login with password and external mfa for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )

        cred = self.add_test_user_external_mfa_cred(user)
        authn = AuthnData(
            cred_id=cred.key,
            timestamp=utc_now(),
            external=ExternalAuthnData(
                issuer="issuer.example.com", authn_context="http://id.elegnamnden.se/loa/1.0/loa3"
            ),
        )

        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.EDUID_MFA,
            credentials=["pw", authn],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.EDUID_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_refeds_mfa_external_mfa(self) -> None:
        """
        Test login with password and external mfa for verified user, request REFEDS_MFA.

        Expect the response Authn to be REFEDS_MFA.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn, identity_type=IdentityType.NIN, unique_value="190101011234"
        )
        cred = self.add_test_user_external_mfa_cred(user)
        authn = AuthnData(
            cred_id=cred.key,
            timestamp=utc_now(),
            external=ExternalAuthnData(
                issuer="issuer.example.com", authn_context="http://id.elegnamnden.se/loa/1.0/loa3"
            ),
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", authn],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_refeds_mfa_fido_al1_with_al3_mfa(self) -> None:
        """
        Test login with password and fido for not verified user, request REFEDS_MFA.

        Expect the response Authn to be REFEDS_MFA, eduPersonAssurance AL1
        """
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user
        user.credentials.add(_U2F_SWAMID_AL3)
        self.app.central_userdb.save(user)
        out = self._get_login_response_authn(
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", _U2F_SWAMID_AL3],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_get_login_response_eduid_mfa_no_multifactor(self) -> None:
        """
        Test login with password, request EDUID_MFA.

        This is not a failure, the user just needs to do MFA too.
        """
        out = self._get_login_response_authn(req_class_ref=EduidAuthnContextClass.EDUID_MFA, credentials=["pw"])
        self._check_login_response_authn(authn_result=out, message=IdPMsg.mfa_required, expect_success=False)

    def test_get_login_response_refeds_mfa_no_multifactor(self) -> None:
        """
        Test login with password, request EDUID_MFA.

        This is not a failure, the user just needs to do MFA too.
        """
        out = self._get_login_response_authn(req_class_ref=EduidAuthnContextClass.REFEDS_MFA, credentials=["pw"])
        self._check_login_response_authn(authn_result=out, message=IdPMsg.mfa_required, expect_success=False)

    def test_get_login_digg_loa2_fido_mfa(self) -> None:
        """
        Test login with password and fido mfa for verified user, request DIGG_LOA2.

        Expect the response Authn to be DIGG_LOA2.
        """
        self.get_user_set_identity(
            self.test_user.eppn,
            identity_type=IdentityType.NIN,
            unique_value="190101011234",
            proofing_method=IdentityProofingMethod.BANKID,
        )
        self.add_test_user_security_key(credential=_U2F_SWAMID_AL3)
        user = self.app.userdb.get_user_by_eppn(self.test_user.eppn)
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
            credentials=["pw", _U2F_SWAMID_AL3],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.DIGG_LOA2,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_digg_loa2_fido_mfa_no_identity_proofing_method(self) -> None:
        """
        Test login with password and external mfa for verified user, request DIGG_LOA2.

        Expect the response Authn to be DIGG_LOA2.
        """
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user
        user.credentials.add(_U2F_SWAMID_AL3)
        self.app.userdb.save(user)

        # test with allowed identity proofing methods
        for nin_verified_by in ["bankid", "eidas", "eduid-eidas", "eduid-idproofing-letter"]:
            user = self.get_user_set_identity(
                self.test_user.eppn,
                identity_type=IdentityType.NIN,
                unique_value="190101011234",
                identity_verified_by=nin_verified_by,
            )
            out = self._get_login_response_authn(
                user=user,
                req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
                credentials=["pw", _U2F_SWAMID_AL3],
            )
            self._check_login_response_authn(
                authn_result=out,
                message=IdPMsg.proceed,
                accr=EduidAuthnContextClass.DIGG_LOA2,
                assurance_profile=self.app.conf.swamid_assurance_profile_3,
            )

        # test with not allowed identity proofing methods
        for nin_verified_by in ["lookup_mobile_proofing", "oidc_proofing"]:
            user = self.get_user_set_identity(
                self.test_user.eppn,
                identity_type=IdentityType.NIN,
                unique_value="190101011234",
                identity_verified_by=nin_verified_by,
            )
            out = self._get_login_response_authn(
                user=user,
                req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
                credentials=["pw", _U2F_SWAMID_AL3],
            )
            self._check_login_response_authn(
                authn_result=out,
                message=IdPMsg.identity_proofing_method_not_allowed,
                expect_success=False,
                expect_error=True,
            )

    def test_get_login_digg_loa2_external_mfa(self) -> None:
        """
        Test login with password and external mfa for verified user, request DIGG_LOA2.

        Expect the response Authn to be DIGG_LOA2.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn,
            identity_type=IdentityType.NIN,
            unique_value="190101011234",
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
        )
        cred = self.add_test_user_external_mfa_cred(user)
        authn = AuthnData(
            cred_id=cred.key,
            timestamp=utc_now(),
            external=ExternalAuthnData(
                issuer="issuer.example.com", authn_context="http://id.elegnamnden.se/loa/1.0/loa3"
            ),
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
            credentials=["pw", authn],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.DIGG_LOA2,
            assurance_profile=self.app.conf.swamid_assurance_profile_3,
        )

    def test_get_login_digg_loa2_identity_proofing_method_not_allowed(self) -> None:
        """
        Test login with password and external mfa for verified user, request DIGG_LOA2.

        Expect the response Authn to fail with error message for frontend.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn,
            identity_type=IdentityType.NIN,
            unique_value="190101011234",
            proofing_method=IdentityProofingMethod.TELEADRESS,
        )
        cred = self.add_test_user_external_mfa_cred(user)
        authn = AuthnData(
            cred_id=cred.key,
            timestamp=utc_now(),
            external=ExternalAuthnData(
                issuer="issuer.example.com", authn_context="http://id.elegnamnden.se/loa/1.0/loa3"
            ),
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
            credentials=["pw", authn],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.identity_proofing_method_not_allowed,
            expect_success=False,
            expect_error=True,
        )

    def test_get_login_digg_loa2_only_sso_force_reauth(self) -> None:
        """
        Test login with password and external mfa for verified user, request DIGG_LOA2.

        Expect reauthenticate if only SSO credentials are available
        """
        user = self.get_user_set_identity(
            self.test_user.eppn,
            identity_type=IdentityType.NIN,
            unique_value="190101011234",
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
        )
        cred = self.add_test_user_external_mfa_cred(user)
        authn = AuthnData(
            cred_id=cred.key,
            timestamp=utc_now(),
            external=ExternalAuthnData(
                issuer="issuer.example.com", authn_context="http://id.elegnamnden.se/loa/1.0/loa3"
            ),
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
            credentials=["pw", authn],
            add_credentials_to_this_request=False,
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.must_authenticate,
            expect_success=False,
            expect_error=False,
        )

    def test_get_login_digg_loa2_mfa_proofing_method_not_allowed(self) -> None:
        """
        Test login with password and external mfa for verified user, request DIGG_LOA2.

        Expect the response Authn to fail with message for frontend.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn,
            identity_type=IdentityType.NIN,
            unique_value="190101011234",
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.DIGG_LOA2,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.mfa_proofing_method_not_allowed,
            expect_success=False,
            expect_error=True,
        )

    def test_get_login_eidas_loa_nf_low_not_AL2(self) -> None:
        """
        Test login with password and external mfa for verified user, request DIGG_LOA2.

        Expect the response Authn to fail with message for frontend.
        """
        user = self.get_user_set_identity(
            self.test_user.eppn,
            identity_type=IdentityType.EIDAS,
            unique_value="eidas_prid",
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
            eidas_loa=EIDASLoa.NF_LOW,
        )
        out = self._get_login_response_authn(
            user=user,
            req_class_ref=EduidAuthnContextClass.REFEDS_MFA,
            credentials=["pw", "u2f"],
        )
        self._check_login_response_authn(
            authn_result=out,
            message=IdPMsg.proceed,
            accr=EduidAuthnContextClass.REFEDS_MFA,
            assurance_profile=self.app.conf.swamid_assurance_profile_1,
        )

    def test_forceauthn_request(self) -> None:
        """ForceAuthn can apparently be either 'true' or '1'.

        https://lists.oasis-open.org/archives/security-services/201402/msg00019.html
        """
        force_authn = {
            "True": True,
            "true": True,
            "false": False,
            "1": True,
            "0": False,
        }
        for value, expected in force_authn.items():
            xmlstr = f"""
            <ns0:AuthnRequest xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"
                  AssertionConsumerServiceURL="https://mfa-check.swamid.se/Shibboleth.sso/SAML2/POST"
                  Destination="https://unittest-idp.example.edu/sso/post" ForceAuthn="{value}"
                  ID="_9f482d6c6ace2867a69c53671fbf09c6"
                  IssueInstant="2021-05-27T21:53:24Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                  Version="2.0">
                <ns1:Issuer>https://mfa-check.swamid.se/shibboleth</ns1:Issuer>
                <ns0:NameIDPolicy AllowCreate="1" />
                <ns0:RequestedAuthnContext>
                  <ns1:AuthnContextClassRef>https://refeds.org/profile/mfa</ns1:AuthnContextClassRef>
                </ns0:RequestedAuthnContext>
            </ns0:AuthnRequest>
            """
            info = {"SAMLRequest": b64encode(xmlstr)}

            x = self._parse_SAMLRequest(
                info,
                binding=BINDING_HTTP_POST,
                idp=self.app.IDP,
                debug=True,
                verify_request_signatures=False,
            )

            assert x.force_authn == expected

    def test_service_info(self) -> None:
        with self.app.test_request_context():
            ticket = self._make_login_ticket(EduidAuthnContextClass.PASSWORD_PT)

            assert ticket.service_info == ServiceInfo(
                display_name={"sv": "eduID Sverige (Utveckling)", "en": "eduID Sweden (Developer)"}
            )
