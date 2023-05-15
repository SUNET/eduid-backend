#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from base64 import b64encode
from io import BytesIO
from typing import Optional

from flask import Blueprint, abort, request

from eduid.common.rpc.exceptions import MsgTaskFailed
from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.phone import PhoneNumber
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.session import session
from eduid.webapp.phone.app import current_phone_app as current_app
from eduid.webapp.phone.helpers import PhoneMsg
from eduid.webapp.phone.schemas import (
    CaptchaCompleteRequest,
    CaptchaResponse,
    PhoneResponseSchema,
    PhoneSchema,
    SimplePhoneSchema,
    VerificationCodeSchema,
)
from eduid.webapp.phone.verifications import SMSThrottleException, send_verification_code, verify_phone_number
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import make_short_code

phone_views = Blueprint("phone", __name__, url_prefix="", template_folder="templates")


@phone_views.route("/all", methods=["GET"])
@MarshalWith(PhoneResponseSchema)
@require_user
def get_all_phones(user: User) -> FluxData:
    """
    view to get a listing of all phones for the logged in user.
    """

    phones = {"phones": user.phone_numbers.to_list_of_dicts()}
    return success_response(payload=phones)


@phone_views.route("/new", methods=["POST"])
@UnmarshalWith(PhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_phone(user: User, number: str, verified, primary) -> FluxData:
    """
    view to add a new phone to the user data of the currently
    logged in user.

    Returns a listing of  all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.info("Trying to save unconfirmed phone number")
    current_app.logger.debug(f"Phone number: {number}")

    new_phone = PhoneNumber(number=number, created_by="phone", is_verified=False, is_primary=False)
    proofing_user.phone_numbers.add(new_phone)

    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.error("Could not save phone number, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info("Saved unconfirmed phone number")
    current_app.stats.count(name="mobile_save_unconfirmed_mobile", value=1)

    try:
        send_verification_code(proofing_user, number)
    except SMSThrottleException:
        return error_response(message=PhoneMsg.still_valid_code)
    except MsgTaskFailed:
        return error_response(message=CommonMsg.temp_problem)

    current_app.stats.count(name="mobile_send_verification_code", value=1)
    phones = {"phones": proofing_user.phone_numbers.to_list_of_dicts()}
    return success_response(payload=phones, message=PhoneMsg.save_success)


@phone_views.route("/primary", methods=["POST"])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_primary(user: User, number: str) -> FluxData:
    """
    view to mark one of the (verified) phone numbers of the logged in user
    as the primary phone number.

    Returns a listing of all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.info("Trying to save phone number as primary")
    current_app.logger.debug(f"Phone number: {number}")

    phone_element = proofing_user.phone_numbers.find(number)
    if not phone_element:
        current_app.logger.error("Phone number not found, could not save it as primary")
        return error_response(message=PhoneMsg.unknown_phone)

    if not phone_element.is_verified:
        current_app.logger.error("Could not save phone number as primary, phone number unconfirmed")
        return error_response(message=PhoneMsg.unconfirmed_primary)

    proofing_user.phone_numbers.set_primary(phone_element.key)
    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.error("Could not save phone number as primary, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info("Phone number set as primary")
    current_app.stats.count(name="mobile_set_primary", value=1)
    phones = {"phones": proofing_user.phone_numbers.to_list_of_dicts()}
    return success_response(payload=phones, message=PhoneMsg.primary_success)


@phone_views.route("/verify", methods=["POST"])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def verify(user: User, code: str, number: str) -> FluxData:
    """
    view to mark one of the (unverified) phone numbers of the logged in user
    as verified.

    Returns a listing of  all phones for the logged in user.
    """

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.info("Trying to save phone number as verified")
    current_app.logger.debug(f"Phone number: {number}")

    if not session.phone.captcha.completed:
        # don't allow verification without captcha completion
        # this is so that a malicious user can't send a lot of SMS.
        return error_response(message=PhoneMsg.captcha_not_completed)

    db = current_app.proofing_statedb
    state = db.get_state_by_eppn_and_mobile(proofing_user.eppn, number)
    if not state:
        current_app.logger.error("Proofing state not found")
        return error_response(message=PhoneMsg.unknown_phone)

    timeout = current_app.conf.phone_verification_timeout
    if state.is_expired(timeout):
        current_app.logger.info("Proofing state is expired. Removing the state.")
        current_app.logger.debug(f"Proofing state: {state}")
        current_app.proofing_statedb.remove_state(state)
        return error_response(message=PhoneMsg.code_invalid)

    if code != state.verification.verification_code:
        current_app.logger.info("Invalid verification code")
        current_app.logger.debug(f"Proofing state: {state}")
        return error_response(message=PhoneMsg.code_invalid)

    try:
        verify_phone_number(state, proofing_user)
        current_app.logger.info("Phone number successfully verified")
        phones = {
            "phones": proofing_user.phone_numbers.to_list_of_dicts(),
        }
        return success_response(payload=phones, message=PhoneMsg.verify_success)
    except UserOutOfSync:
        current_app.logger.info("Could not confirm phone number, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)


@phone_views.route("/remove", methods=["POST"])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def post_remove(user: User, number: str) -> FluxData:
    """
    view to remove one of the phone numbers of the logged in user.

    Returns a listing of  all phones for the logged in user.
    """
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    current_app.logger.info("Trying to remove phone number")
    current_app.logger.debug(f"Phone number: {number}")

    phone = proofing_user.phone_numbers.find(number)
    if not phone:
        current_app.logger.error("Tried to remove a non existing phone number")
        return error_response(message=PhoneMsg.unknown_phone)

    proofing_user.phone_numbers.remove_handling_primary(phone.key)

    try:
        save_and_sync_user(proofing_user)
    except UserOutOfSync:
        current_app.logger.error("Could not remove phone number, data out of sync")
        return error_response(message=CommonMsg.out_of_sync)

    current_app.logger.info("Phone number removed")
    current_app.stats.count(name="mobile_remove_success", value=1)

    phones = {"phones": proofing_user.phone_numbers.to_list_of_dicts()}
    return success_response(payload=phones, message=PhoneMsg.removal_success)


@phone_views.route("/resend-code", methods=["POST"])
@UnmarshalWith(SimplePhoneSchema)
@MarshalWith(PhoneResponseSchema)
@require_user
def resend_code(user: User, number: str) -> FluxData:
    """
    view to resend a new verification code for one of the (unverified)
    phone numbers of the logged in user.

    Returns a listing of  all phones for the logged in user.
    """
    current_app.logger.info("Trying to send new verification code")
    current_app.logger.debug(f"Phone number: {number}")

    if not user.phone_numbers.find(number):
        current_app.logger.error("Unknown phone number used for resend code")
        return error_response(message=CommonMsg.out_of_sync)

    try:
        send_verification_code(user, number)
    except SMSThrottleException:
        return error_response(message=PhoneMsg.still_valid_code)
    except MsgTaskFailed:
        return error_response(message=CommonMsg.temp_problem)

    current_app.logger.info("New verification code sent")
    current_app.stats.count(name="mobile_resend_code", value=1)

    phones = {"phones": user.phone_numbers.to_list_of_dicts()}
    return success_response(payload=phones, message=PhoneMsg.resend_success)


@phone_views.route("/get-code", methods=["GET"])
def get_code() -> str:
    """
    Backdoor to get the verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.conf):
            eppn = request.args.get("eppn")
            phone = request.args.get("phone")
            if not eppn or not phone:
                # TODO: Return something better when the ENUMs have landed in master
                current_app.logger.error("Missing eppn or phone")
                abort(400)
            state = current_app.proofing_statedb.get_state_by_eppn_and_mobile(eppn, phone)
            if state and state.verification and state.verification.verification_code:
                return state.verification.verification_code
    except Exception:
        current_app.logger.exception("Someone tried to use the backdoor to get the verification code for a phone")

    abort(400)


@phone_views.route("/get-captcha", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(CaptchaResponse)
def captcha_request() -> FluxData:
    if session.phone.captcha.completed:
        return error_response(message=PhoneMsg.captcha_already_completed)

    session.phone.captcha.internal_answer = make_short_code(digits=current_app.conf.captcha_code_length)
    session.phone.captcha.bad_attempts = 0
    data = current_app.captcha_image_generator.generate_image(chars=session.signup.captcha.internal_answer)
    with BytesIO() as f:
        data.save(fp=f, format="PNG", optimize=True)
        return success_response(
            payload={"captcha_img": f"data:image/png;base64,{b64encode(f.getvalue()).decode('utf-8')}"},
        )


@phone_views.route("/captcha", methods=["POST"])
@UnmarshalWith(CaptchaCompleteRequest)
@MarshalWith(PhoneResponseSchema)
def captcha_response(recaptcha_response: Optional[str] = None, internal_response: Optional[str] = None) -> FluxData:
    """
    Check for humanness.
    """
    current_app.logger.info("Checking captcha")

    captcha_verified = False

    if session.phone.captcha.bad_attempts >= current_app.conf.captcha_max_bad_attempts:
        current_app.logger.info("Too many incorrect captcha attempts")
        # bad attempts is reset when a new captcha is generated
        return error_response(message=PhoneMsg.captcha_failed)

    # add a backdoor to bypass recaptcha checks for humanness,
    # to be used in testing environments for automated integration tests.
    if check_magic_cookie(current_app.conf):
        current_app.logger.info("Using BACKDOOR to verify captcha during phone verification!")
        captcha_verified = True
        if internal_response is not None and internal_response != current_app.conf.captcha_backdoor_code:
            # used for testing failed captcha attempts
            current_app.logger.info("Incorrect captcha backdoor code")
            captcha_verified = False

    # common path with no backdoor
    # if recaptcha_response and not captcha_verified:
    #     remote_ip = request.remote_addr
    #     if not remote_ip:
    #         raise RuntimeError("No remote IP address found")
    #     if current_app.conf.recaptcha_public_key and current_app.conf.recaptcha_private_key:
    #         captcha_verified = verify_recaptcha(current_app.conf.recaptcha_private_key, recaptcha_response, remote_ip)
    #     else:
    #         current_app.logger.info("Missing configuration for reCaptcha!")
    # elif internal_response and not captcha_verified:
    #     if session.signup.captcha.internal_answer is None:
    #         return error_response(message=SignupMsg.captcha_not_requested)
    #     captcha_verified = internal_response == session.signup.captcha.internal_answer

    if not captcha_verified:
        current_app.logger.info("Captcha failed")
        session.phone.captcha.bad_attempts += 1
        return error_response(message=PhoneMsg.captcha_failed)

    current_app.logger.info("Captcha completed")
    session.phone.captcha.completed = True
    return success_response(payload={"state": session.phone.to_dict()})
