from enum import unique

from pydantic import BaseModel, Field

from eduid.common.models.generic import HttpUrlStr
from eduid.webapp.common.api.messages import TranslatableMsg


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
