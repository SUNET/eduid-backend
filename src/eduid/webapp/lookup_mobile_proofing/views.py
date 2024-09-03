from flask import Blueprint

from eduid.common.rpc.exceptions import AmTaskFailed, LookupMobileTaskFailed, MsgTaskFailed, NoNavetData
from eduid.userdb import User
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, can_verify_nin, require_user
from eduid.webapp.common.api.helpers import add_nin_to_user, verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.lookup_mobile_proofing import schemas
from eduid.webapp.lookup_mobile_proofing.app import current_mobilep_app as current_app
from eduid.webapp.lookup_mobile_proofing.helpers import MobileMsg, create_proofing_state, match_mobile_to_user

__author__ = "lundberg"

mobile_proofing_views = Blueprint("lookup_mobile_proofing", __name__, url_prefix="", template_folder="templates")


@mobile_proofing_views.route("/proofing", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def get_state(user: User) -> FluxData:
    return success_response()


@mobile_proofing_views.route("/proofing", methods=["POST"])
@UnmarshalWith(schemas.LookupMobileProofingRequestSchema)
@MarshalWith(schemas.LookupMobileProofingResponseSchema)
@can_verify_nin
@require_user
def proofing(user: User, nin: str) -> FluxData:
    current_app.logger.info(f"Trying to verify nin via mobile number for user {user}.")
    current_app.logger.debug(f"NIN: {nin}.")

    # Add nin as not verified to the user
    proofing_state = create_proofing_state(user, nin)
    proofing_user = add_nin_to_user(user, proofing_state)

    # Get list of verified mobile numbers
    verified_mobiles = [item.number for item in user.phone_numbers.to_list() if item.is_verified]
    if not verified_mobiles:
        return error_response(message=MobileMsg.no_phone)

    try:
        proofing_log_entry = match_mobile_to_user(user, nin, verified_mobiles)
    except LookupMobileTaskFailed:
        current_app.stats.count("validate_nin_by_mobile_error")
        return error_response(message=MobileMsg.lookup_error)
    except NoNavetData:
        current_app.logger.exception("No data returned from Navet")
        return error_response(message=CommonMsg.no_navet_data)
    except MsgTaskFailed:
        current_app.stats.count("navet_error")
        return error_response(message=CommonMsg.navet_error)

    if proofing_log_entry:
        try:
            # Verify nin for user
            if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
                return error_response(message=CommonMsg.temp_problem)
            return success_response(message=MobileMsg.verify_success)
        except AmTaskFailed:
            current_app.logger.exception("Verifying nin for user failed")
            return error_response(message=CommonMsg.temp_problem)
        except LockedIdentityViolation:
            current_app.logger.exception("Verifying NIN for user failed")
            return error_response(message=CommonMsg.locked_identity_not_matching)

    return error_response(message=MobileMsg.no_match)
