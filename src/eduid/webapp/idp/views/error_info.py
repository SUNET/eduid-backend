from flask import Blueprint

from eduid.userdb.credentials import FidoCredential
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.exceptions import ApiException
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import get_user
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.schemas import ErrorInfoResponseSchema

error_info_views = Blueprint("error_info", __name__, url_prefix="")


@error_info_views.route("/error_info", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(ErrorInfoResponseSchema)
def error_info() -> FluxData:
    current_app.logger.debug("\n\n")
    current_app.logger.debug("--- Error info ---")

    try:
        user = get_user()
    except ApiException:
        user = None

    if not user:
        return success_response(payload={"logged_in": False})

    has_locked_nin = bool(user.locked_identity.nin)
    has_verified_nin = bool(user.identities.nin and user.identities.nin.is_verified)
    fido_credentials = user.credentials.filter(FidoCredential)
    has_mfa = bool(fido_credentials)

    payload = {
        "eppn": user.eppn,
        "has_locked_nin": has_locked_nin,
        "has_mfa": has_mfa,
        "has_verified_nin": has_verified_nin,
        "logged_in": True,
    }

    return success_response(payload=payload)
