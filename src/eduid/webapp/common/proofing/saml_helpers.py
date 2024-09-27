import logging

from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml_models import BaseSessionInfo
from eduid.webapp.common.authn.session_info import SessionInfo

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def is_required_loa(
    session_info: SessionInfo, required_loa: list[str], authentication_context_map: dict[str, str]
) -> bool:
    parsed_session_info = BaseSessionInfo(**session_info)
    if not required_loa:
        logger.debug(f"No LOA required, allowing {parsed_session_info.authn_context}")
        return True
    loa_uris = [authentication_context_map.get(loa) for loa in required_loa]
    if not loa_uris:
        logger.error(f"LOA {required_loa} not found in configuration (authentication_context_map), disallowing")
        return False
    if parsed_session_info.authn_context in loa_uris:
        logger.debug(f"Asserted authn context {parsed_session_info.authn_context} matches required {required_loa}")
        return True
    logger.error("Asserted authn context class does not match required class")
    logger.error(f"Asserted: {parsed_session_info.authn_context}")
    logger.error(f"Required: {loa_uris} ({required_loa})")
    return False


def authn_ctx_to_loa(session_info: SessionInfo, authentication_context_map: dict[str, str]) -> str | None:
    """Lookup short name (such as 'loa3') for an authentication context class we've received."""
    parsed = BaseSessionInfo(**session_info)
    for k, v in authentication_context_map.items():
        if v == parsed.authn_context:
            return k
    return None


def authn_context_class_to_loa(session_info: BaseSessionInfo, authentication_context_map: dict[str, str]) -> str | None:
    for key, value in authentication_context_map.items():
        if value == session_info.authn_context:
            return key
    return None


def is_valid_authn_instant(session_info: SessionInfo, max_age: int = 60) -> bool:
    """
    :param session_info: The SAML2 session_info
    :param max_age: Max time (in seconds) since authn that is to be allowed
    :return: True if authn instant is no older than max_age
    """
    parsed_session_info = BaseSessionInfo(**session_info)
    now = utc_now()
    age = now - parsed_session_info.authn_instant
    if age.total_seconds() <= max_age:
        logger.debug(
            f"Re-authn is valid, authn instant {parsed_session_info.authn_instant}, age {age}, max_age {max_age}s"
        )
        return True
    logger.error(f"Authn instant {parsed_session_info.authn_instant} too old (age {age}, max_age {max_age} seconds)")
    return False


def create_metadata(config: SPConfig):
    return entity_descriptor(config)
