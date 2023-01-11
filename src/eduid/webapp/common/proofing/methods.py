import logging
from abc import ABC
from dataclasses import dataclass
from typing import List, Optional, Union

from flask import request
from pydantic import ValidationError

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo
from eduid.webapp.svipe_id.helpers import SvipeDocumentUserInfo, SvipeTokenResponse

logger = logging.getLogger(__name__)


@dataclass
class SessionInfoParseResult:
    error: Optional[TranslatableMsg] = None
    info: Optional[Union[NinSessionInfo, ForeignEidSessionInfo, SvipeDocumentUserInfo]] = None


@dataclass(frozen=True)
class ProofingMethod(ABC):
    method: str
    framework: TrustFramework
    finish_url: str

    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        raise NotImplementedError("Subclass must implement parse_session_info")

    def formatted_finish_url(self, app_name: str, authn_id: str) -> Optional[str]:
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


def get_proofing_method(
    method: Optional[str],
    frontend_action: str,
    config: ProofingConfigMixin,
    fallback_redirect_url: Optional[str] = None,
) -> Optional[Union[ProofingMethodFreja, ProofingMethodEidas, ProofingMethodSvipe]]:
    # look up the finish_url here (when receiving the request, rather than in the ACS)
    # to be able to fail fast if frontend requests an action that backend isn't configured for
    finish_url = config.frontend_action_finish_url.get(frontend_action, fallback_redirect_url)
    if not finish_url:
        logger.warning(f"No finish_url for frontend_action {frontend_action} (fallback: {fallback_redirect_url})")
        return None

    if method == "freja":
        if not config.freja_idp:
            logger.warning(f"Missing configuration freja_idp required for proofing method {method}")
            return None
        return ProofingMethodFreja(
            finish_url=finish_url,
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
            finish_url=finish_url,
            framework=TrustFramework.EIDAS,
            idp=config.foreign_identity_idp,
            method=method,
            required_loa=config.foreign_required_loa,  # TODO: True Required LOA is likely higher here when verifying credentials
        )
    if method == "svipe_id":
        return ProofingMethodSvipe(
            method=method,
            framework=TrustFramework.SVIPE,
            finish_url=finish_url,
        )

    logger.warning(f"Unknown proofing method {method}")
    return None
