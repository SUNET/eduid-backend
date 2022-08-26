import logging
from abc import ABC
from dataclasses import dataclass
from typing import List, Optional, Union
from flask import request

from pydantic import ValidationError

from eduid.common.config.base import MagicCookieMixin, ProofingConfigMixin
from eduid.userdb import User
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.identity import IdentityElement
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo

logger = logging.getLogger(__name__)


@dataclass
class SessionInfoParseResult:
    error: Optional[TranslatableMsg] = None
    info: Optional[Union[NinSessionInfo, ForeignEidSessionInfo]] = None


@dataclass(frozen=True)
class ProofingMethod(ABC):
    finish_url: Optional[str]
    framework: TrustFramework
    idp: str
    method: str
    required_loa: List[str]

    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        raise NotImplementedError('Subclass must implement parse_session_info')


class ProofingMethodFreja(ProofingMethod):
    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = NinSessionInfo(**session_info)
            logger.debug(f'session info: {parsed_session_info}')
        except ValidationError:
            logger.exception('missing attribute in SAML response')
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        if backdoor:
            # change asserted nin to nin from the integration test cookie
            magic_cookie_nin = request.cookies.get('nin')
            if magic_cookie_nin is None:
                logger.error("Bad nin cookie")
                return SessionInfoParseResult(error=ProofingMsg.malformed_identity)
            parsed_session_info.attributes.nin = magic_cookie_nin

        return SessionInfoParseResult(info=parsed_session_info)


class ProofingMethodEidas(ProofingMethod):
    def parse_session_info(self, session_info: SessionInfo, backdoor: bool) -> SessionInfoParseResult:
        try:
            parsed_session_info = ForeignEidSessionInfo(**session_info)
            logger.debug(f'session info: {parsed_session_info}')
        except ValidationError:
            logger.exception('missing attribute in SAML response')
            return SessionInfoParseResult(error=ProofingMsg.attribute_missing)

        return SessionInfoParseResult(info=parsed_session_info)


def get_proofing_method(
    method: Optional[str], frontend_action: str, config: ProofingConfigMixin
) -> Optional[ProofingMethod]:
    # look up the finish_url here (when receiving the request, rather than in the ACS)
    # to be able to fail fast if frontend requests an action that backend isn't configured for
    finish_url = config.frontend_action_finish_url.get(frontend_action)

    if method == 'freja':
        if not config.freja_idp:
            logger.warning(f'Missing configuration freja_idp required for proofing method {method}')
            return None
        return ProofingMethodFreja(
            finish_url=finish_url,
            framework=TrustFramework.SWECONN,
            idp=config.freja_idp,
            method=method,
            required_loa=config.required_loa,
        )
    if method == 'eidas':
        if not config.foreign_identity_idp:
            logger.warning(f'Missing configuration foreign_identity_idp required for proofing method {method}')
            return None
        return ProofingMethodEidas(
            finish_url=finish_url,
            framework=TrustFramework.EIDAS,
            idp=config.foreign_identity_idp,
            method=method,
            required_loa=config.foreign_required_loa,
        )
    return None
