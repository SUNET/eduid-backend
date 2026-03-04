from flask import Blueprint, abort
from requests.exceptions import ConnectionError as RequestsConnectionError

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import AmTaskFailed, MsgTaskFailed, NoAddressFound
from eduid.userdb import User
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.logs import LetterProofing
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, can_verify_nin, require_user
from eduid.webapp.common.api.helpers import add_nin_to_user, check_magic_cookie, verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.letter_proofing import pdf, schemas
from eduid.webapp.letter_proofing.app import current_letterp_app as current_app
from eduid.webapp.letter_proofing.ekopost import EkopostException
from eduid.webapp.letter_proofing.helpers import LetterMsg, check_state, create_proofing_state, get_address, send_letter

__author__ = "lundberg"

letter_proofing_views = Blueprint("letter_proofing", __name__, url_prefix="", template_folder="templates")


@letter_proofing_views.route("/proofing", methods=["GET"])
@MarshalWith(schemas.LetterProofingResponseSchema)
@require_user
def get_state(user: User) -> FluxData:
    current_app.logger.info(f"Getting proofing state for user {user}")
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)

    if proofing_state:
        current_app.logger.info(f"Found proofing state for user {user}")
        result = check_state(proofing_state)
        if result.is_expired and current_app.conf.backwards_compat_remove_expired_state:
            current_app.logger.info(f"Backwards-compat removing expired state for user {user}")
            current_app.proofing_statedb.remove_state(proofing_state)
            current_app.stats.count("letter_expired")
            return success_response(message=LetterMsg.no_state)
        if result.message == LetterMsg.not_sent:
            # "Not sent" (which is really Unfinished state) is an error for other views, such as verify_code below,
            # but it is not an error for this simple state fetching view. The frontend currently fetches this state on
            # login and we don't want an error notification to be shown to all users that requested a letter without
            # a registered address (folkbokföringsadress) for example.
            return success_response(message=LetterMsg.not_sent)
        return result.to_response()
    return success_response(message=LetterMsg.no_state)


@letter_proofing_views.route("/proofing", methods=["POST"])
@UnmarshalWith(schemas.LetterProofingRequestSchema)
@MarshalWith(schemas.LetterProofingResponseSchema)
@can_verify_nin
@require_user
def proofing(user: User, nin: str) -> FluxData:
    current_app.logger.info(f"Send letter for user {user} initiated")
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    _state_in_db = proofing_state is not None

    if not proofing_state:
        # No existing proofing state was found, create a new one
        proofing_state = create_proofing_state(user.eppn, nin)
        current_app.logger.info(f"Created proofing state for user {user}")

    # Add the nin used to initiate the proofing state to the user
    # NOOP if the user already have the nin
    add_nin_to_user(user, proofing_state)

    if proofing_state.proofing_letter.is_sent:
        current_app.logger.info("A letter has already been sent to the user.")
        current_app.logger.debug(f"Proofing state: {proofing_state.to_dict()}")
        result = check_state(proofing_state)
        if result.error:
            # error message
            return result.to_response()
        if not result.is_expired:
            return result.to_response()

        current_app.logger.info("The letter has expired. Sending a new one...")
        current_app.proofing_statedb.remove_state(proofing_state)
        current_app.logger.info(f"Removed {proofing_state}")
        current_app.stats.count("letter_expired")
        proofing_state = create_proofing_state(user.eppn, nin)
        _state_in_db = False
        current_app.logger.info(f"Created new {proofing_state}")

    try:
        address = get_address(user, proofing_state)
    except NoAddressFound:
        current_app.logger.error("No data returned from Navet")
        return error_response(message=LetterMsg.address_not_found)
    except MsgTaskFailed:
        current_app.logger.exception(f"Navet lookup failed for user {user}")
        current_app.stats.count("navet_error")
        return error_response(message=CommonMsg.navet_error)

    # Set and save official address
    proofing_state.proofing_letter.address = address
    current_app.proofing_statedb.save(proofing_state, is_in_database=_state_in_db)

    try:
        campaign_id = send_letter(user, proofing_state)
        current_app.stats.count("letter_sent")
    except pdf.AddressFormatException:
        current_app.logger.exception("Failed formatting address")
        current_app.stats.count("address_format_error")
        current_app.proofing_statedb.remove_state(proofing_state)
        return error_response(message=LetterMsg.bad_address)
    except EkopostException:
        current_app.logger.exception("Ekopost returned an error")
        current_app.stats.count("ekopost_error")
        current_app.proofing_statedb.remove_state(proofing_state)
        return error_response(message=CommonMsg.temp_problem)
    except RequestsConnectionError as e:
        current_app.logger.error(f"Error connecting to Ekopost: {e}")
        current_app.proofing_statedb.remove_state(proofing_state)
        return error_response(message=CommonMsg.temp_problem)

    # Save the users updated proofing state
    proofing_state.proofing_letter.transaction_id = campaign_id
    proofing_state.proofing_letter.is_sent = True
    proofing_state.proofing_letter.sent_ts = utc_now()
    current_app.proofing_statedb.save(proofing_state)
    result = check_state(proofing_state)
    result.message = LetterMsg.letter_sent
    return result.to_response()


@letter_proofing_views.route("/verify-code", methods=["POST"])
@UnmarshalWith(schemas.VerifyCodeRequestSchema)
@MarshalWith(schemas.VerifyCodeResponseSchema)
@require_user
def verify_code(user: User, code: str) -> FluxData:
    current_app.logger.info(f"Verifying code for user {user}")
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)

    if not proofing_state:
        return error_response(message=LetterMsg.no_state)

    # Check if provided code matches the one in the letter
    if code != proofing_state.nin.verification_code:
        current_app.logger.error(f"Verification code for user {user} does not match")
        # TODO: Throttling to discourage an adversary to try brute force
        return error_response(message=LetterMsg.wrong_code)

    state_info = check_state(proofing_state)
    if state_info.error:
        return state_info.to_response()

    if state_info.is_expired:
        # This is not an error in the get_state view, but here it is an error so 'upgrade' it.
        state_info.error = True
        current_app.logger.warning(f"Tried to validate expired state: {proofing_state}")
        return state_info.to_response()

    try:
        # Fetch registered address again, to save the address of record at time of verification.
        official_address = get_address(user, proofing_state)
    except MsgTaskFailed:
        current_app.logger.exception(f"Navet lookup failed for user {user}")
        current_app.stats.count("navet_error")
        return error_response(message=CommonMsg.navet_error)

    letter_sent_to = None
    if proofing_state.proofing_letter.address:
        letter_sent_to = proofing_state.proofing_letter.address.model_dump()

    proofing_log_entry = LetterProofing(
        eppn=user.eppn,
        created_by="eduid_letter_proofing",
        nin=proofing_state.nin.number,
        letter_sent_to=letter_sent_to,
        transaction_id=proofing_state.proofing_letter.transaction_id,
        user_postal_address=official_address,
        proofing_version="2016v1",
    )
    # Verify nin for user
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    try:
        if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
            current_app.logger.error(f"Failed verifying NIN for user {proofing_user}")
            return error_response(message=CommonMsg.temp_problem)
    except AmTaskFailed:
        current_app.logger.exception("Verifying NIN for user failed")
        return error_response(message=CommonMsg.temp_problem)
    except LockedIdentityViolation:
        current_app.logger.exception("Verifying NIN for user failed")
        return error_response(message=CommonMsg.locked_identity_not_matching)

    current_app.logger.info(f"Verified code for user {user}")
    # Remove proofing state
    current_app.proofing_statedb.remove_state(proofing_state)
    current_app.stats.count(name="nin_verified")

    return success_response(
        payload={"identities": proofing_user.identities.to_frontend_format()},
        message=LetterMsg.verify_success,
    )


@letter_proofing_views.route("/get-code", methods=["GET"])
@require_user
def get_code(user: User) -> str:
    """
    Backdoor to get the verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
            if state and state.nin and state.nin.verification_code:
                return state.nin.verification_code
    except Exception:
        current_app.logger.exception(f"{user} tried to use the backdoor to get the letter verification code for a NIN")
    abort(400)
