import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from eduid.common.config.base import FrontendAction
from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.common.testing_base import normalised_data
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.identity import FrejaLoaLevel, FrejaRegistrationLevel, PridPersistence
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.proofing.methods import ProofingMethods
from eduid.webapp.common.session.eduid_session import EduidSession, SessionFactory
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.namespaces import (
    EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK,
    AuthnRequestRef,
    ExternalMfaSignupBankIDIdentity,
    ExternalMfaSignupEIDASIdentity,
    ExternalMfaSignupFrejaEIDForeignIdentity,
    ExternalMfaSignupFrejaEIDIdentity,
    ExternalMfaSignupIdentity,
    ExternalMfaSignupSwedenConnectIdentity,
    FrejaEIDNamespace,
    OidcEidAuthnRequest,
    OidcEidNamespace,
    OIDCState,
    RP_AuthnRequest,
    RPAuthnData,
    SP_AuthnRequest,
)
from eduid.webapp.common.session.redis_session import GENERATION_KEY
from eduid.webapp.common.session.tests.test_eduid_session import SessionTestApp, SessionTestConfig

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TestNameSpaceBase(EduidAPITestCase[SessionTestApp]):
    app: SessionTestApp

    @classmethod
    def load_app(cls, config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logger.debug("Starting SessionTestApp")
        session_config = load_config(typ=SessionTestConfig, app_name="testing", ns="webapp", test_config=config)
        app = SessionTestApp(session_config)
        logger.debug("Started SessionTestApp")
        app.session_interface = SessionFactory(app.conf)
        return app

    def get_session(self, meta: SessionMeta, new: bool = True) -> EduidSession:
        assert isinstance(self.app.session_interface, SessionFactory)
        base_session = self.app.session_interface.manager.get_session(meta=meta, new=new)
        return EduidSession(app=self.app, meta=meta, base_session=base_session, new=new)


class TestNamespace(TestNameSpaceBase):
    def test_to_dict_from_dict(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        session = self.get_session(meta=_meta)
        assert session.idp.sso_cookie_val is None

        session.idp.sso_cookie_val = "abc"
        session.signup.email.verification_code = "test"

        session._serialize_namespaces()
        out = session._session.to_dict()
        assert out.pop(GENERATION_KEY)  # new sessions get a generation marker, outside the namespaces
        normalised_out = normalised_data(out, exclude_keys=["ts"])

        assert normalised_out == {
            "signup": {
                "user_created": False,
                "email": {"completed": False, "verification_code": "test", "bad_attempts": 0},
                "invite": {"initiated_signup": False, "completed": False},
                "name": {},
                "tou": {"completed": False},
                "captcha": {"bad_attempts": 0, "completed": False},
                "credentials": {"completed": False, "custom_password": False},
            },
            "idp": {"sso_cookie_val": "abc", "pending_requests": {}},
        }, f"Actual result: {normalised_out}"

        session.persist()

        # Validate that the session can be loaded again
        loaded_session = self.get_session(meta=_meta, new=False)
        # ...and that it serialises to the same data again
        assert normalised_out == normalised_data(
            loaded_session._session.to_dict(), exclude_keys=["ts", GENERATION_KEY]
        ), f"Actual result: {normalised_out}"

    def test_to_dict_from_dict_with_timestamp(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        first = self.get_session(meta=_meta)

        assert first.idp.sso_cookie_val is None

        first.idp.sso_cookie_val = "abc"
        first.idp.ts = datetime.fromisoformat("2020-09-13T12:26:40+00:00")

        first._serialize_namespaces()
        out = first._session.to_dict()
        assert out.pop(GENERATION_KEY)

        assert out == {
            "idp": {"sso_cookie_val": "abc", "pending_requests": {}, "ts": "2020-09-13T12:26:40Z"},
        }

        first.persist()

        # Validate that the session can be loaded again
        second = self.get_session(meta=_meta, new=False)
        # ...and that it serialises to the same data that was persisted
        assert normalised_data(out, exclude_keys=["ts"]) == normalised_data(
            second._session.to_dict(), exclude_keys=["ts", GENERATION_KEY]
        )

        assert second.idp.sso_cookie_val == first.idp.sso_cookie_val
        assert second.idp.ts == first.idp.ts

    def test_clear_namespace(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        first = self.get_session(meta=_meta)
        first.signup.email.address = "test@example.com"
        first.signup.email.verification_code = "123456"
        first.persist()
        # load session again and clear it
        second = self.get_session(meta=_meta, new=False)
        assert second.signup.email.address == "test@example.com"
        assert second.signup.email.verification_code == "123456"
        second.signup.clear()
        second.signup.email.address = "test@example.com"
        second.persist()
        # load session one more time and make sure verification_code is empty
        third = self.get_session(meta=_meta, new=False)
        assert third.signup.email.address == "test@example.com"
        assert third.signup.email.verification_code is None


class TestAuthnNamespace(TestNameSpaceBase):
    def test_sp_authns_cleanup(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        sess = self.get_session(meta=_meta)
        for i in range(15):
            sess.authn.sp.authns[AuthnRequestRef(str(i))] = SP_AuthnRequest(
                frontend_action=FrontendAction.LOGIN, finish_url="some_url"
            )
        assert len(sess.authn.sp.authns) == 15, f"Expected 15 authns got {len(sess.authn.sp.authns)}"
        sess.persist()
        # load the session again

        sess = self.get_session(meta=_meta, new=False)
        assert len(sess.authn.sp.authns) == 10, f"Expected 10 authns got {len(sess.authn.sp.authns)}"

    def test_sp_authns_overwrite(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        sess1 = self.get_session(meta=_meta)
        for i in range(5):
            sess1.authn.sp.authns[AuthnRequestRef(str(i))] = SP_AuthnRequest(
                frontend_action=FrontendAction.LOGIN, finish_url="some_url"
            )
        sess1.persist()
        # load the session again
        sess2 = self.get_session(meta=_meta, new=False)
        # this next read should not change anything in the session
        sess2.authn.sp.get_latest_authn()
        sess2.persist()
        assert sess1._session._raw_data == sess2._session._raw_data


# --- Standalone tests for ExternalMfaSignupIdentity and the new optional field ---


def test_sp_authn_request_external_mfa_default_none() -> None:
    req = SP_AuthnRequest(
        frontend_action=FrontendAction.SIGNUP_EXTERNAL_MFA,
        finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
    )
    assert req.external_mfa_signup_identity is None


def test_sp_authn_request_external_mfa_roundtrip() -> None:
    identity = ExternalMfaSignupBankIDIdentity(
        given_name="Anna",
        surname="Andersson",
        nin="198001011234",
        framework=TrustFramework.BANKID,
        loa="uncertified-loa3",
        issuer="bankid",
        transaction_id="test-transaction-id",
    )
    req = SP_AuthnRequest(
        frontend_action=FrontendAction.SIGNUP_EXTERNAL_MFA,
        finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
        external_mfa_signup_identity=identity,
    )
    dumped = req.model_dump()
    rebuilt = SP_AuthnRequest(**dumped)
    assert isinstance(rebuilt.external_mfa_signup_identity, ExternalMfaSignupBankIDIdentity)
    assert rebuilt.external_mfa_signup_identity == identity


def test_rp_authn_request_has_external_mfa_field() -> None:
    # freja_eid uses RP_AuthnRequest (OIDC) — the same optional field must exist
    assert "external_mfa_signup_identity" in RP_AuthnRequest.model_fields


def test_rp_authn_data_authns_cleanup() -> None:
    """Only the most recently created authns (by created_ts) are retained when serializing."""
    rp = RPAuthnData()
    now = utc_now()
    states = [OIDCState(str(uuid.uuid4())) for _ in range(15)]
    for i, state in enumerate(states):
        rp.authns[state] = RP_AuthnRequest(
            authn_id=state,
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            finish_url="some_url",
            created_ts=now + timedelta(seconds=i),
        )

    assert len(rp.authns) == 15

    dumped = rp.model_dump()

    assert set(dumped["authns"].keys()) == {str(s) for s in states[5:]}


def test_rp_authn_request_oidc_fields_roundtrip() -> None:
    state = OIDCState(str(uuid.uuid4()))
    authn_req = RP_AuthnRequest(
        authn_id=state,
        frontend_action=FrontendAction.VERIFY_IDENTITY,
        finish_url="some_url",
        nonce="a-nonce",
        code_verifier="a-code-verifier",
        redirect_uri="https://rp.example.com/callback",
    )

    rebuilt = RP_AuthnRequest.model_validate(authn_req.model_dump())

    assert rebuilt.nonce == "a-nonce"
    assert rebuilt.code_verifier == "a-code-verifier"
    assert rebuilt.redirect_uri == "https://rp.example.com/callback"


def test_rp_authn_data_old_session_with_authlib_cache() -> None:
    """A session saved before authlib was removed still loads, and the stale authlib_cache is dropped."""
    state = OIDCState(str(uuid.uuid4()))
    old_session_data = {
        "rp": {
            "authlib_cache": {f"_state_freja_eid_{state}": "state-value"},
            "authns": {},
        }
    }

    namespace = FrejaEIDNamespace.from_dict(old_session_data)

    assert not hasattr(namespace.rp, "authlib_cache")
    assert "authlib_cache" not in namespace.to_dict()["rp"]
    assert "authlib_cache" not in namespace.rp.model_dump()


def test_sp_authn_request_external_mfa_eidas_roundtrip() -> None:
    from eduid.userdb.identity import PridPersistence

    identity = ExternalMfaSignupEIDASIdentity(
        authn_context_class="authn_context_class",
        country_code="DE",
        date_of_birth=datetime(1990, 6, 15, tzinfo=UTC),
        eidas_person_identifier="eidas_person_identifier",
        framework=TrustFramework.EIDAS,
        given_name="Karla",
        issuer="eidas_issuer",
        loa="eidas_sub",
        prid="DE:abc123",
        prid_persistence=PridPersistence.A,
        surname="Müller",
        transaction_id="transaction_id",
    )
    req = SP_AuthnRequest(
        frontend_action=FrontendAction.SIGNUP_EXTERNAL_MFA,
        finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
        external_mfa_signup_identity=identity,
    )
    rebuilt = SP_AuthnRequest(**req.model_dump())
    assert isinstance(rebuilt.external_mfa_signup_identity, ExternalMfaSignupEIDASIdentity)
    assert rebuilt.external_mfa_signup_identity == identity


def test_sp_authn_request_external_mfa_freja_foreign_roundtrip() -> None:
    from eduid.userdb.identity import FrejaLoaLevel, FrejaRegistrationLevel

    identity = ExternalMfaSignupFrejaEIDForeignIdentity(
        country_code="DK",
        date_of_birth=datetime(1985, 3, 15, tzinfo=UTC),
        document_number="123456789",
        document_type="passport",
        framework=TrustFramework.FREJA,
        given_name="Frida",
        issuer="freja eid",
        issuing_country="DK",
        loa="freja-loa3_nr",
        loa_level=FrejaLoaLevel.LOA3_NR,
        personal_identity_number="123456789",
        registration_level=FrejaRegistrationLevel.PLUS,
        surname="Fredriksen",
        transaction_id="test_transaction_id",
        user_id="unique_freja_user",
    )
    req = RP_AuthnRequest(
        authn_id=OIDCState("test_authn_id"),
        method=ProofingMethods.FREJA_EID.value,
        frontend_action=FrontendAction.SIGNUP_EXTERNAL_MFA,
        finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
        external_mfa_signup_identity=identity,
    )
    rebuilt = RP_AuthnRequest(**req.model_dump())
    assert isinstance(rebuilt.external_mfa_signup_identity, ExternalMfaSignupFrejaEIDForeignIdentity)
    assert rebuilt.external_mfa_signup_identity == identity


# --- Standalone tests for SignupExternalMfa and the external_mfa field on Signup ---


def test_signup_external_mfa_default_none() -> None:
    from eduid.webapp.common.session.namespaces import Signup

    sns = Signup()
    assert sns.external_mfa is None


def test_signup_external_mfa_bankid_roundtrip() -> None:
    from eduid.userdb.credentials.external import TrustFramework
    from eduid.webapp.common.session.namespaces import Signup, SignupExternalMfa

    ident = ExternalMfaSignupBankIDIdentity(
        framework=TrustFramework.BANKID,
        given_name="Anna",
        surname="Andersson",
        nin="198001011234",
        issuer="bankid",
        loa="uncertified-loa3",
        transaction_id="test-transaction-id",
    )

    ext = SignupExternalMfa(
        app_name="bankid",
        method=ProofingMethods.BANKID.value,
        authn_id=AuthnRequestRef("abc-123"),
        loa="loa3",
        authn_instant=datetime(2026, 4, 24, tzinfo=UTC),
        ident=ident,
    )
    sns = Signup(external_mfa=ext)
    rebuilt = Signup(**sns.model_dump())
    assert rebuilt.external_mfa == ext


def test_signup_external_mfa_eidas_roundtrip() -> None:
    from eduid.userdb.credentials.external import TrustFramework
    from eduid.userdb.identity import PridPersistence
    from eduid.webapp.common.session.namespaces import Signup, SignupExternalMfa

    ident = ExternalMfaSignupEIDASIdentity(
        country_code="DE",
        date_of_birth=datetime(1990, 6, 15, tzinfo=UTC),
        eidas_person_identifier="eidas_person_identifier",
        given_name="Karla",
        surname="Müller",
        prid="DE:abc",
        prid_persistence=PridPersistence.A,
        transaction_id="transaction_id",
        issuer="eidas_issuer",
        framework=TrustFramework.EIDAS,
        loa="eidas_sub",
        authn_context_class="authn_context_class",
    )
    ext = SignupExternalMfa(
        app_name="eidas",
        method=ProofingMethods.EIDAS.value,
        authn_id="oidc-state",
        loa="eidas_sub",
        authn_instant=datetime(2026, 4, 24, tzinfo=UTC),
        ident=ident,
    )
    sns = Signup(external_mfa=ext)
    rebuilt = Signup(**sns.model_dump())
    assert rebuilt.external_mfa == ext


def test_oidceid_namespace_roundtrip() -> None:
    state = OIDCState(str(uuid.uuid4()))
    identity = ExternalMfaSignupSwedenConnectIdentity(
        framework=TrustFramework.SWECONN,
        given_name="Signe",
        surname="Svensson",
        issuer="swedenconnect",
        loa="loa3",
        nin="198001011234",
        authn_context_class="authn_context_class",
    )
    namespace = OidcEidNamespace()
    namespace.rp.authns[state] = OidcEidAuthnRequest(
        authn_id=state,
        frontend_action=FrontendAction.VERIFY_IDENTITY,
        finish_url="some_url",
        oidc_issuer="https://op.example.com",
        external_mfa_signup_identity=identity,
    )

    rebuilt = OidcEidNamespace.from_dict(namespace.to_dict())

    assert isinstance(rebuilt.rp.authns[state], OidcEidAuthnRequest)
    assert rebuilt.rp.authns[state].oidc_issuer == "https://op.example.com"
    assert rebuilt.rp.authns[state].external_mfa_signup_identity == identity


@pytest.mark.parametrize("issuer", [None, ""])
def test_oidceid_authn_request_requires_issuer(issuer: str | None) -> None:
    kwargs: dict[str, Any] = {
        "authn_id": OIDCState("a-state"),
        "frontend_action": FrontendAction.VERIFY_IDENTITY,
        "finish_url": "some_url",
    }
    if issuer is not None:
        kwargs["oidc_issuer"] = issuer
    with pytest.raises(ValidationError):
        OidcEidAuthnRequest(**kwargs)


def test_oidceid_namespace_authn_without_issuer_fails_to_load() -> None:
    """A stored oidceid authn lacking oidc_issuer is rejected: from_dict raises, as for other invalid namespace data."""
    state = OIDCState(str(uuid.uuid4()))
    data = {
        "rp": {
            "authns": {
                state: {
                    "authn_id": state,
                    "frontend_action": FrontendAction.VERIFY_IDENTITY.value,
                    "finish_url": "some_url",
                }
            }
        }
    }

    with pytest.raises(ValidationError):
        OidcEidNamespace.from_dict(data)


def test_single_op_rp_authn_request_has_no_oidc_issuer() -> None:
    """freja_eid/svipe_id/orcid are single-OP; their shared request model has no issuer and old sessions load."""
    assert "oidc_issuer" not in RP_AuthnRequest.model_fields
    state = OIDCState(str(uuid.uuid4()))
    old_data = {
        "rp": {
            "authns": {
                state: {
                    "authn_id": state,
                    "frontend_action": FrontendAction.VERIFY_IDENTITY.value,
                    "finish_url": "some_url",
                }
            }
        }
    }

    namespace = FrejaEIDNamespace.from_dict(old_data)

    assert namespace.rp.authns[state].external_mfa_signup_identity is None


def _identity_kwargs(cls: type[ExternalMfaSignupIdentity], framework: TrustFramework) -> dict[str, Any]:
    common: dict[str, Any] = {"framework": framework, "given_name": "A", "surname": "B", "issuer": "i", "loa": "loa3"}
    dob = datetime(1980, 1, 1, tzinfo=UTC)
    extra: dict[type[ExternalMfaSignupIdentity], dict[str, Any]] = {
        ExternalMfaSignupBankIDIdentity: {"nin": "198001011234", "transaction_id": "t"},
        ExternalMfaSignupSwedenConnectIdentity: {"nin": "198001011234", "authn_context_class": "c"},
        ExternalMfaSignupEIDASIdentity: {
            "authn_context_class": "c",
            "country_code": "DK",
            "date_of_birth": dob,
            "eidas_person_identifier": "e",
            "prid": "p",
            "prid_persistence": PridPersistence.A,
            "transaction_id": "t",
        },
        ExternalMfaSignupFrejaEIDIdentity: {
            "date_of_birth": dob,
            "document_number": "1",
            "document_type": "Passport",
            "loa_level": FrejaLoaLevel.LOA3,
            "registration_level": FrejaRegistrationLevel.PLUS,
            "user_id": "u",
            "nin": "198001011234",
            "transaction_id": "t",
        },
        ExternalMfaSignupFrejaEIDForeignIdentity: {
            "country_code": "DK",
            "date_of_birth": dob,
            "personal_identity_number": "p",
            "document_number": "1",
            "document_type": "Passport",
            "issuing_country": "DK",
            "loa_level": FrejaLoaLevel.LOA3,
            "registration_level": FrejaRegistrationLevel.PLUS,
            "user_id": "u",
            "transaction_id": "t",
        },
    }
    return {**common, **extra[cls]}


def test_identity_framework_mapping_covers_all_subclasses() -> None:
    def _all_subclasses(c: type[ExternalMfaSignupIdentity]) -> set[type[ExternalMfaSignupIdentity]]:
        found: set[type[ExternalMfaSignupIdentity]] = set()
        for sub in c.__subclasses__():
            found.add(sub)
            found |= _all_subclasses(sub)
        return found

    assert set(EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK) == _all_subclasses(ExternalMfaSignupIdentity)


@pytest.mark.parametrize("cls", list(EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK))
@pytest.mark.parametrize("framework", list(TrustFramework))
def test_identity_class_framework_must_agree(cls: type[ExternalMfaSignupIdentity], framework: TrustFramework) -> None:
    kwargs = _identity_kwargs(cls, framework)
    if framework == EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK[cls]:
        assert cls(**kwargs).framework == framework
    else:
        with pytest.raises(ValidationError):
            cls(**kwargs)


@pytest.mark.parametrize("cls", list(EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK))
def test_rp_authn_request_identity_roundtrip_picks_right_class(cls: type[ExternalMfaSignupIdentity]) -> None:
    ident = cls(**_identity_kwargs(cls, EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK[cls]))
    state = OIDCState("a-state")
    req = RP_AuthnRequest(
        authn_id=state,
        frontend_action=FrontendAction.VERIFY_IDENTITY,
        finish_url="some_url",
        external_mfa_signup_identity=ident,
    )

    rebuilt = RP_AuthnRequest.model_validate(req.model_dump())

    assert type(rebuilt.external_mfa_signup_identity) is cls
    assert rebuilt.external_mfa_signup_identity == ident


@pytest.mark.parametrize("cls", list(EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK))
def test_signup_external_mfa_roundtrip_picks_right_class(cls: type[ExternalMfaSignupIdentity]) -> None:
    from eduid.webapp.common.session.namespaces import SignupExternalMfa

    ident = cls(**_identity_kwargs(cls, EXTERNAL_MFA_SIGNUP_IDENTITY_FRAMEWORK[cls]))
    data = {
        "app_name": "oidceid",
        "method": "m",
        "authn_id": "a-state",
        "loa": "loa3",
        "authn_instant": datetime(2026, 4, 24, tzinfo=UTC),
        "ident": ident.model_dump(),
    }
    ext = SignupExternalMfa.model_validate(data)

    rebuilt = SignupExternalMfa.model_validate(ext.model_dump())

    assert type(rebuilt.ident) is cls
