import logging
from abc import ABC
from dataclasses import dataclass

from flask import request
from pydantic import ValidationError

from eduid.common.config.base import FrontendAction, ProofingConfigMixin
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo
from eduid.webapp.freja_eid.helpers import FrejaEIDDocumentUserInfo
from eduid.webapp.svipe_id.helpers import SvipeDocumentUserInfo

logger = logging.getLogger(__name__)


@dataclass
class SessionInfoParseResult:
    error: TranslatableMsg | None = None
    info: (
        NinSessionInfo
        | ForeignEidSessionInfo
        | SvipeDocumentUserInfo
        | BankIDSessionInfo
        | FrejaEIDDocumentUserInfo
        | None
    ) = None


@dataclass(frozen=True)
class ProofingMethod(ABC):
    method: str
    framework: TrustFramework
    finish_url: str

    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        raise NotImplementedError("Subclass must implement parse_session_info")

    def formatted_finish_url(self, app_name: str, authn_id: str) -> str | None:
        if not self.finish_url:
            return None
        return self.finish_url.format(app_name=app_name, authn_id=authn_id)


@dataclass(frozen=True)
class ProofingMethodSAML(ProofingMethod):
    idp: str
    required_loa: list[str]

    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        raise NotImplementedError("Subclass must implement parse_session_info")


@dataclass(frozen=True)
class ProofingMethodFreja(ProofingMethodSAML):
    idp: str
    required_loa: list[str]

    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = NinSessionInfo(**session_info)
            logger.debug(f"session info: {parsed_session_info}")
        except ValidationError:
            logger.exception("missing attribute in SAML response")
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        if backdoor:
            # change asserted nin to nin from the integration test cookie
            magic_cookie_nin = request.cookies.get("nin")
            if magic_cookie_nin is None:
                logger.error("Bad nin cookie")
                return SessionInfoParseResult(error=ProofingMsg.malformed_identity)
            logger.debug(f"Using nin from magic cookie: {magic_cookie_nin}")
            parsed_session_info.attributes.nin = magic_cookie_nin

        return SessionInfoParseResult(info=parsed_session_info)


@dataclass(frozen=True)
class ProofingMethodEidas(ProofingMethodSAML):
    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = ForeignEidSessionInfo(**session_info)
            logger.debug(f"session info: {parsed_session_info}")
        except ValidationError:
            logger.exception("missing attribute in SAML response")
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        return SessionInfoParseResult(info=parsed_session_info)


@dataclass(frozen=True)
class ProofingMethodBankID(ProofingMethodSAML):
    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = BankIDSessionInfo(**session_info)
            logger.debug(f"session info: {parsed_session_info}")
        except ValidationError:
            logger.exception("missing attribute in SAML response")
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        return SessionInfoParseResult(info=parsed_session_info)


@dataclass(frozen=True)
class ProofingMethodSvipe(ProofingMethod):
    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = SvipeDocumentUserInfo(**session_info)
            logger.debug(f"session info: {parsed_session_info}")
        except ValidationError:
            logger.exception("missing claim in userinfo response")
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        # verify session info data
        # document should not have expired
        if parsed_session_info.document_expiry_date < utc_now().date():
            logger.error(f"Document has expired {parsed_session_info.document_expiry_date}")
            return SessionInfoParseResult(error=ProofingMsg.session_info_not_valid)

        return SessionInfoParseResult(info=parsed_session_info)


@dataclass(frozen=True)
class ProofingMethodFrejaEID(ProofingMethod):
    required_registration_level: list[str]
    required_loa: list[str]

    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = FrejaEIDDocumentUserInfo(**session_info)
            logger.debug(f"session info: {parsed_session_info}")
        except ValidationError:
            logger.exception("missing claim in userinfo response")
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        # verify session info data
        # document should not have expired
        expiration_date = parsed_session_info.document.expiration_date
        if expiration_date < utc_now().date():
            logger.error(f"Document has expired {expiration_date}")
            return SessionInfoParseResult(error=ProofingMsg.session_info_not_valid)

        return SessionInfoParseResult(info=parsed_session_info)


def get_proofing_method(
    method: str | None,
    frontend_action: FrontendAction,
    config: ProofingConfigMixin,
) -> (
    ProofingMethodFreja
    | ProofingMethodEidas
    | ProofingMethodSvipe
    | ProofingMethodBankID
    | ProofingMethodFrejaEID
    | None
):
    authn_params = config.frontend_action_authn_parameters.get(frontend_action)
    assert authn_params is not None  # please mypy

    if method == "freja":
        if not config.freja_idp:
            logger.warning(f"Missing configuration freja_idp required for proofing method {method}")
            return None
        return ProofingMethodFreja(
            finish_url=authn_params.finish_url,
            framework=TrustFramework.SWECONN,
            idp=config.freja_idp,
            method=method,
            required_loa=config.required_loa,
        )
    if method == "eidas":
        if not config.foreign_identity_idp:
            logger.warning(f"Missing configuration foreign_identity_idp required for proofing method {method}")
            return None
        return ProofingMethodEidas(
            finish_url=authn_params.finish_url,
            framework=TrustFramework.EIDAS,
            idp=config.foreign_identity_idp,
            method=method,
            # TODO: True Required LOA is likely higher here when verifying credentials
            required_loa=config.foreign_required_loa,
        )
    if method == "svipe_id":
        return ProofingMethodSvipe(
            method=method,
            framework=TrustFramework.SVIPE,
            finish_url=authn_params.finish_url,
        )
    if method == "bankid":
        if not config.bankid_idp:
            logger.warning(f"Missing configuration bankid_idp required for proofing method {method}")
            return None
        return ProofingMethodBankID(
            method=method,
            framework=TrustFramework.BANKID,
            finish_url=authn_params.finish_url,
            idp=config.bankid_idp,
            required_loa=config.bankid_required_loa,
        )
    if method == "freja_eid":
        return ProofingMethodFrejaEID(
            method=method,
            framework=TrustFramework.FREJA,
            finish_url=authn_params.finish_url,
            required_registration_level=config.freja_eid_required_registration_level,
            required_loa=config.freja_eid_required_loa,
        )

    logger.warning(f"Unknown proofing method {method}")
    return None
