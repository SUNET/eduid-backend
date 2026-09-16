import logging
from enum import unique

from pydantic import BaseModel, Field

from eduid.common.models.generic import HttpUrlStr
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.session import session

__author__ = "lundberg"


logger = logging.getLogger(__name__)


class SessionOidcCache:
    # Used to store json-encoded data (OAuth->BaseOAuth->FrameworkIntegration)
    @staticmethod
    def get(key: str) -> str | None:
        logger.debug(f"Getting {key} from session.orcid.rp.authlib_cache")
        return session.orcid.rp.authlib_cache.get(key)

    @staticmethod
    def set(key: str, value: str, expires: int | None = None) -> None:
        session.orcid.rp.authlib_cache[key] = value
        logger.debug(f"Set {key}={value} (expires={expires}) in session.orcid.rp.authlib_cache")

    @staticmethod
    def delete(key: str) -> None:
        del session.orcid.rp.authlib_cache[key]
        logger.debug(f"Deleted {key} from session.orcid.rp.authlib_cache")


@unique
class OrcidMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # ORCID account already connected to eduID account
    already_connected = "orc.already_connected"
    # Authorization error at ORCID
    authz_error = "orc.authorization_fail"
    # nonce received from ORCID not known
    unknown_nonce = "orc.unknown_nonce"
    # The 'sub' of userinfo does not match 'sub' of ID Token for user
    sub_mismatch = "orc.sub_mismatch"
    # ORCID proofing data saved for user
    authz_success = "orc.authorization_success"
    # frontend action not supported
    frontend_action_not_supported = "orc.frontend_action_not_supported"


class OrcidUserinfo(BaseModel):
    orcid: HttpUrlStr = Field(alias="id")
    sub: str
    name: str | None = None
    family_name: str
    given_name: str
