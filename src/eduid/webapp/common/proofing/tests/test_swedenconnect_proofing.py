"""
Unit tests for the assurance (LOA) gating guards in the Sweden Connect proofing functions.

The proofing functions are constructed directly with real session info objects, a real config and real
user objects. Only the ambient ``current_proofing_app`` is replaced.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture, MockType

from eduid.common.config.base import ProofingConfigMixin, SwedenConnectProofingConfigMixin
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.base import CredentialProofingMethod
from eduid.userdb.credentials.fido import Webauthn
from eduid.userdb.identity import EIDASIdentity, EIDASLoa, PridPersistence
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.proofing.messages import SwedenConnectProofingMsg
from eduid.webapp.common.proofing.swedenconnect.proofing import (
    BankIDProofingFunctions,
    EidasProofingFunctions,
    FrejaProofingFunctions,
    UnsupportedMethod,
    get_swedenconnect_proofing_functions,
)
from eduid.webapp.common.proofing.swedenconnect.session_info import (
    BankIDSessionInfo,
    ForeignEidSessionInfo,
    NinSessionInfo,
)

_ISSUER = "https://idp.example.com"
_LOA_PREFIX = "http://id.elegnamnden.se/loa/1.0/"
_PROOFING_MODULE = "eduid.webapp.common.proofing.swedenconnect.proofing"


class _Config(SwedenConnectProofingConfigMixin):
    pass


@pytest.fixture(autouse=True)
def proofing_app(mocker: MockerFixture) -> MockType:
    app: MockType = mocker.MagicMock()
    mocker.patch(f"{_PROOFING_MODULE}.current_proofing_app", new=app)
    app.conf.app_name = "testing"
    return app


def _authn_info(loa: str | None) -> list[tuple[str, list[str], str]]:
    return [(f"{_LOA_PREFIX}{loa}", [], "2026-01-01T12:00:00Z")]


def _foreign_ava(
    given_name: str = "Ulla", surname: str = "Alm", date_of_birth: str = "1978-01-01", persistence: str = "B"
) -> dict[str, list[str]]:
    return {
        "prid": ["SE:1234"],
        "pridPersistence": [persistence],
        "eidasPersonIdentifier": ["XX/YY/1234"],
        "dateOfBirth": [date_of_birth],
        "givenName": [given_name],
        "sn": [surname],
        "c": ["DK"],
        "transactionIdentifier": ["tx-1"],
    }


def _eidas(authn_info: list[tuple[str, list[str], str]], **ava_kwargs: str) -> EidasProofingFunctions:
    session_info = ForeignEidSessionInfo(issuer=_ISSUER, authn_info=authn_info, ava=_foreign_ava(**ava_kwargs))
    return EidasProofingFunctions(session_info=session_info, app_name="testing", config=_Config(), backdoor=False)


def _freja() -> FrejaProofingFunctions:
    session_info = NinSessionInfo(
        issuer=_ISSUER,
        authn_info=_authn_info("loa3"),
        ava={
            "personalIdentityNumber": ["197801012369"],
            "givenName": ["Ulla"],
            "sn": ["Alm"],
            "dateOfBirth": ["1978-01-01"],
        },
    )
    return FrejaProofingFunctions(session_info=session_info, app_name="testing", config=_Config(), backdoor=False)


def _bankid() -> BankIDProofingFunctions:
    session_info = BankIDSessionInfo(
        issuer=_ISSUER,
        authn_info=_authn_info("uncertified-loa3"),
        ava={
            "personalIdentityNumber": ["197801012369"],
            "givenName": ["Ulla"],
            "sn": ["Alm"],
            "transactionIdentifier": ["bf5d125b"],
            "authContextParams": ["uidId=abc;"],
        },
    )
    return BankIDProofingFunctions(session_info=session_info, app_name="testing", config=_Config(), backdoor=False)


def _credential() -> Credential:
    return Webauthn(
        keyhandle="kh",
        app_id="app",
        credential_data="data",
        authenticator="cross-platform",
    )


def _user(
    locked_persistence: PridPersistence | None = None, given_name: str = "Ulla", surname: str = "Alm"
) -> ProofingUser:
    user = ProofingUser(eppn="hubba-bubba", given_name=given_name, surname=surname)
    if locked_persistence is not None:
        locked = EIDASIdentity(
            created_by="testing",
            prid="SE:OLD",
            prid_persistence=locked_persistence,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime(1978, 1, 1, tzinfo=UTC),
            country_code="DK",
            is_verified=True,
        )
        user.locked_identity.add(locked)
    return user


# --- Freja ---


@pytest.mark.parametrize("loa", [None, "loa2", "loa4", "uncertified-loa3", "eidas-nf-high"])
def test_freja_mark_credential_rejects_non_loa3(loa: str | None) -> None:
    cred = _credential()
    result = _freja().mark_credential_as_verified(cred, loa)
    assert result.error == SwedenConnectProofingMsg.authn_context_mismatch_eidas
    assert result.credential is None
    assert cred.is_verified is False


def test_freja_mark_credential_accepts_loa3() -> None:
    cred = _credential()
    result = _freja().mark_credential_as_verified(cred, "loa3")
    assert result.error is None
    assert result.credential is cred
    assert cred.is_verified is True
    assert cred.proofing_method == CredentialProofingMethod.SWAMID_AL3_MFA


# --- eIDAS verify_identity ---


def test_eidas_verify_identity_rejects_unmapped_loa(proofing_app: MockType) -> None:
    # authn context that is not in the loa map -> no current LOA
    fn = _eidas([("http://example.com/unknown-loa", [], "2026-01-01T12:00:00Z")])
    result = fn.verify_identity(_user())
    assert result.error == SwedenConnectProofingMsg.authn_context_mismatch_eidas
    assert result.user is None
    proofing_app.private_userdb.save.assert_not_called()


def test_eidas_verify_identity_rejects_missing_authn_context(proofing_app: MockType) -> None:
    fn = _eidas([("", [], "2026-01-01T12:00:00Z")])
    result = fn.verify_identity(_user())
    assert result.error == SwedenConnectProofingMsg.authn_context_mismatch_eidas
    proofing_app.private_userdb.save.assert_not_called()


# --- eIDAS mark_credential_as_verified ---


@pytest.mark.parametrize("loa", [None, "loa2", "loa3", "uncertified-loa3", "eidas-low"])
def test_eidas_mark_credential_rejects_unrelated_loa(loa: str | None) -> None:
    cred = _credential()
    result = _eidas(_authn_info("eidas-nf-high")).mark_credential_as_verified(cred, loa)
    assert result.error == SwedenConnectProofingMsg.authn_context_mismatch_eidas
    assert result.credential is None
    assert cred.is_verified is False


@pytest.mark.parametrize("loa", ["eidas-nf-sub", "eidas-nf-high"])
def test_eidas_mark_credential_accepts_substantial_and_high(loa: str) -> None:
    cred = _credential()
    result = _eidas(_authn_info("eidas-nf-high")).mark_credential_as_verified(cred, loa)
    assert result.error is None
    assert result.credential is cred
    assert cred.is_verified is True


def test_eidas_mark_credential_rejects_nf_low() -> None:
    # the credential guard follows the configured foreign_required_loa (default eidas-nf-sub/eidas-nf-high)
    cred = _credential()
    result = _eidas(_authn_info("eidas-nf-low")).mark_credential_as_verified(cred, "eidas-nf-low")
    assert result.error == SwedenConnectProofingMsg.authn_context_mismatch_eidas
    assert result.credential is None
    assert cred.is_verified is False


# --- eIDAS _can_replace_identity ---


@pytest.mark.parametrize("persistence", [PridPersistence.B, PridPersistence.C])
def test_eidas_can_replace_identity_all_match(persistence: PridPersistence) -> None:
    assert _eidas(_authn_info("eidas-nf-high"))._can_replace_identity(_user(persistence)) is True


@pytest.mark.parametrize("persistence", [PridPersistence.B, PridPersistence.C])
def test_eidas_cannot_replace_identity_different_surname(persistence: PridPersistence) -> None:
    fn = _eidas(_authn_info("eidas-nf-high"), surname="Berg")
    assert fn._can_replace_identity(_user(persistence)) is False


@pytest.mark.parametrize("persistence", [PridPersistence.B, PridPersistence.C])
def test_eidas_cannot_replace_identity_different_given_name(persistence: PridPersistence) -> None:
    fn = _eidas(_authn_info("eidas-nf-high"), given_name="Kalle")
    assert fn._can_replace_identity(_user(persistence)) is False


def test_eidas_cannot_replace_identity_different_date_of_birth() -> None:
    fn = _eidas(_authn_info("eidas-nf-high"), date_of_birth="1980-02-02")
    assert fn._can_replace_identity(_user(PridPersistence.B)) is False


def test_eidas_cannot_replace_persistence_a_identity() -> None:
    # persistence A is stable, so it is never replaced even if every attribute matches
    assert _eidas(_authn_info("eidas-nf-high"))._can_replace_identity(_user(PridPersistence.A)) is False


def test_eidas_can_replace_when_nothing_locked() -> None:
    assert _eidas(_authn_info("eidas-nf-high"))._can_replace_identity(_user(None)) is True


def test_eidas_verify_identity_rejects_mismatching_locked_identity(proofing_app: MockType) -> None:
    # same date of birth but different surname on a locked persistence-B identity with another prid
    fn = _eidas(_authn_info("eidas-nf-high"), surname="Berg")
    result = fn.verify_identity(_user(PridPersistence.B))
    assert result.error == CommonMsg.locked_identity_not_matching
    proofing_app.private_userdb.save.assert_not_called()


# --- BankID ---


@pytest.mark.parametrize("loa", [None, "loa3", "loa2", "eidas-nf-high"])
def test_bankid_mark_credential_rejects_other_loa(loa: str | None) -> None:
    cred = _credential()
    result = _bankid().mark_credential_as_verified(cred, loa)
    assert result.error == SwedenConnectProofingMsg.authn_context_mismatch_bankid
    assert result.credential is None
    assert cred.is_verified is False


def test_bankid_mark_credential_accepts_uncertified_loa3() -> None:
    cred = _credential()
    result = _bankid().mark_credential_as_verified(cred, "uncertified-loa3")
    assert result.error is None
    assert result.credential is cred
    assert cred.is_verified is True


# --- dispatcher and message values ---


def test_dispatcher_selects_functions_by_session_info_class() -> None:
    for fn in (_freja(), _bankid(), _eidas(_authn_info("eidas-nf-high"))):
        result = get_swedenconnect_proofing_functions(
            session_info=fn.session_info, app_name="testing", config=_Config(), backdoor=False
        )
        assert type(result) is type(fn)


def test_dispatcher_rejects_session_info_subclass() -> None:
    # a subclass must never be routed to another eID's proofing functions
    class _SubNinSessionInfo(NinSessionInfo):
        pass

    sub = _SubNinSessionInfo(
        issuer=_ISSUER,
        authn_info=_authn_info("loa3"),
        ava={
            "personalIdentityNumber": ["197801012369"],
            "givenName": ["Ulla"],
            "sn": ["Alm"],
            "dateOfBirth": ["1978-01-01"],
        },
    )
    with pytest.raises(UnsupportedMethod):
        get_swedenconnect_proofing_functions(session_info=sub, app_name="testing", config=_Config(), backdoor=False)


def test_authn_context_mismatch_message_values_are_stable() -> None:
    # these strings are the frontend contract, shared with the eidas and bankid webapps
    assert SwedenConnectProofingMsg.authn_context_mismatch_eidas.value == "eidas.authn_context_mismatch"
    assert SwedenConnectProofingMsg.authn_context_mismatch_bankid.value == "bankid.authn_context_mismatch"


def test_loa_map_with_duplicate_uris_is_rejected() -> None:
    uri = f"{_LOA_PREFIX}loa3"
    with pytest.raises(ValidationError, match="duplicate URIs"):
        _Config(loa_authn_context_map={"loa3": uri, "eidas-nf-high": uri})


def test_default_loa_map_is_injective() -> None:
    uris = list(_Config().loa_authn_context_map.values())
    assert len(set(uris)) == len(uris)


@pytest.mark.parametrize("loa", ["loa3", "eidas-nf-sub", "eidas-nf-high", "eidas-nf-low"])
def test_current_loa_resolves_labels(loa: str) -> None:
    assert _eidas(_authn_info(loa)).get_current_loa().result == loa


def test_current_loa_is_none_for_unknown_authn_context() -> None:
    assert _eidas([("http://example.com/unknown", [], "2026-01-01T12:00:00Z")]).get_current_loa().result is None


def test_dispatcher_rejects_config_without_loa_mixin() -> None:
    config = ProofingConfigMixin()
    with pytest.raises(TypeError, match="lacks the Sweden Connect LoA config mixin"):
        get_swedenconnect_proofing_functions(
            session_info=_freja().session_info,
            app_name="testing",
            config=config,  # type: ignore[arg-type]
            backdoor=False,
        )


def test_authn_context_loa_map_follows_config_assignment() -> None:
    config = _Config()
    config.loa_authn_context_map = {"custom": "http://example.com/custom"}
    assert config.authn_context_loa_map == {"http://example.com/custom": "custom"}
