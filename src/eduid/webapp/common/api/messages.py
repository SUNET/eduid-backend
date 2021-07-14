# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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
#     3. Neither the name of the SUNET nor the names of its
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
from copy import copy
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import redirect
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.api.schemas.models import FluxResponseStatus


@unique
class TranslatableMsg(str, Enum):
    # some form has failed to validate
    form_errors = 'form-errors'
    # problem synchronzing the account to the central db
    temp_problem = 'Temporary technical problems'
    # The user has changed in the db since it was retrieved
    out_of_sync = 'user-out-of-sync'
    # error in the communications with navet
    navet_error = 'error_navet_task'
    # NIN validation error
    nin_invalid = 'nin needs to be formatted as 18|19|20yymmddxxxx'
    # Email address validation error
    email_invalid = 'email needs to be formatted according to RFC2822'
    still_valid_code = 'still-valid-code'

    # ACTIONS
    # the user corresponding to the action has not been found in the db
    actions_user_not_found = 'mfa.user-not-found'
    # The (mfa|tou|...) action has been completed successfully
    actions_action_completed = 'actions.action-completed'
    # No mfa data sent in authn request
    actions_no_data = 'mfa.no-request-data'
    # Neither u2f nor webauthn data in request to authn
    actions_no_response = 'mfa.no-token-response'
    # The mfa data sent does not correspond to a known mfa token
    actions_unknown_token = 'mfa.unknown-token'
    # Cannot find the text for the he ToU version configured
    actions_no_tou = 'tou.no-tou'
    # The user has not accepted the ToU
    actions_must_accept = 'tou.must-accept'
    # Error synchronizing the ToU acceptance to the central db
    actions_sync_problem = 'tou.sync-problem'
    # for use in the tests
    actions_test_error = 'test error'

    # EIDAS
    # LOA 3 not needed
    eidas_authn_context_mismatch = 'eidas.authn_context_mismatch'
    # no attribute personalIdentityNumber received
    eidas_no_nin_attribute_received = 'eidas.no_nin_attribute_received'
    # re-authentication expired
    eidas_reauthn_expired = 'eidas.reauthn_expired'
    # the token was not used to authenticate this session
    eidas_token_not_in_creds = 'eidas.token_not_in_credentials_used'
    # the personalIdentityNumber from eidas does not correspond
    # to a verified nin in the user's account
    eidas_nin_not_matching = 'eidas.nin_not_matching'
    # successfully verified the token
    eidas_verify_success = 'eidas.token_verify_success'
    # The user already has a verified NIN
    eidas_nin_already_verified = 'eidas.nin_already_verified'
    # Successfully verified the NIN
    eidas_nin_verify_success = 'eidas.nin_verify_success'
    # missing redirect URL for mfa authn
    eidas_no_redirect_url = 'eidas.no_redirect_url'
    # Token not found on the credentials in the user's account
    eidas_token_not_found = 'eidas.token_not_found'

    # EMAIL
    # the requested email is missing
    email_missing = 'emails.missing'
    # the provided email is duplicated
    email_dupe = 'emails.duplicated'
    # success retrieving the account's emails
    email_get_success = 'emails.get-success'
    # A verification mail for that address has been sent recently
    email_throttled = 'emails.throttled'
    # The email has been added, but no verification code has been sent (throttled)
    email_added_and_throttled = 'emails.added-and-throttled'
    # succesfully saved new email address
    email_saved = 'emails.save-success'
    # trying to set as primary an unconfirmed address
    email_unconfirmed_not_primary = 'emails.unconfirmed_address_not_primary'
    # success setting email address as primary
    email_success_primary = 'emails.primary-success'
    # the received verification code was invalid or expired
    email_invalid_code = 'emails.code_invalid_or_expired'
    # unknown email received to set as primary
    email_unknown_email = 'emails.unknown_email'
    # success verifying email
    email_verify_success = 'emails.verification-success'
    # it's not allowed to remove all email addresses
    email_cannot_remove_last = 'emails.cannot_remove_unique'
    # it's not allowed to remove all verified email addresses
    email_cannot_remove_last_verified = 'emails.cannot_remove_unique_verified'
    # success removing an email address
    email_removal_success = 'emails.removal-success'
    # success sending a verification code
    email_code_sent = 'emails.code-sent'

    # GROUP MANAGEMENT
    group_management_user_does_not_exist = 'group.user_does_not_exist'
    group_management_user_to_be_removed_does_not_exist = 'group.user_to_be_removed_does_not_exist'
    group_management_can_not_remove_last_owner = 'group.can_not_remove_last_owner'
    group_management_group_not_found = 'group.group_not_found'
    group_management_invite_not_found = 'group.invite_not_found'
    group_management_create_failed = 'group.create_failed'
    group_management_user_not_owner = 'group.user_not_owner'
    group_management_mail_address_not_verified = 'group.mail_address_not_verified'

    # IDP
    idp_action_required = 'login.action_required'  # Shouldn't actually be returned to the frontend
    idp_assurance_failure = 'login.assurance_failure'
    idp_assurance_not_possible = 'login.assurance_not_possible'
    idp_bad_ref = 'login.bad_ref'
    idp_credential_expired = 'login.credential_expired'
    idp_finished = 'login.finished'
    idp_general_failure = 'login.general_failure'
    idp_mfa_required = 'login.mfa_required'
    idp_mfa_auth_failed = 'login.mfa_auth_failed'
    idp_must_authenticate = 'login.must_authenticate'
    idp_no_sso_session = 'login.no_sso_session'
    idp_not_available = 'login.not_available'
    idp_not_implemented = 'login.not_implemented'
    idp_proceed = 'login.proceed'  # Shouldn't actually be returned to the frontend
    idp_swamid_mfa_required = 'login.swamid_mfa_required'
    idp_tou_not_acceptable = 'login.tou_not_acceptable'
    idp_tou_required = 'login.tou_required'
    idp_user_temporary_locked = 'login.user_temporary_locked'
    idp_user_terminated = 'login.user_terminated'
    idp_wrong_credentials = 'login.wrong_credentials'
    idp_wrong_user = 'login.wrong_user'

    # LETTER PROOFING
    # No letter proofing state found in the db
    letter_proofing_no_state = 'letter.no_state_found'
    # a letter has already been sent
    letter_proofing_already_sent = 'letter.already-sent'
    # the letter has been sent, but enough time has passed to send a new one
    letter_proofing_letter_expired = 'letter.expired'
    # some unspecified problem sending the letter
    letter_proofing_not_sent = 'letter.not-sent'
    # no postal address found
    letter_proofing_address_not_found = 'letter.no-address-found'
    # errors in the format of the postal address
    letter_proofing_bad_address = 'letter.bad-postal-address'
    # letter sent and state saved w/o errors
    letter_proofing_letter_sent = 'letter.saved-unconfirmed'
    # wrong verification code received
    letter_proofing_wrong_code = 'letter.wrong-code'
    # success verifying the code
    letter_proofing_verify_success = 'letter.verification_success'

    # LOOKUP MOBILE
    # the user has no verified phones to use
    lookup_mobile_no_phone = 'no_phone'
    # problems looking up the phone
    lookup_mobile_lookup_error = 'error_lookup_mobile_task'
    # success verifying the NIN with the phone
    lookup_mobile_verify_success = 'lookup_mobile.verification_success'
    # no match for the provided phone number
    lookup_mobile_no_match = 'nins.no-mobile-match'

    # OIDC PROOFING
    # Connection error sending a request to the authz endpoint
    oidc_proofing_no_conn = 'No connection to authorization endpoint'

    # ORCID
    # ORCID account already connected to eduID account
    orcid_already_connected = 'orc.already_connected'
    # Authorization error at ORCID
    orcid_authz_error = 'orc.authorization_fail'
    # proofing state corresponding to ORCID response not found
    orcid_no_state = 'orc.unknown_state'
    # nonce received from ORCID not known
    orcid_unknown_nonce = 'orc.unknown_nonce'
    # The 'sub' of userinfo does not match 'sub' of ID Token for user
    orcid_sub_mismatch = 'orc.sub_mismatch'
    # ORCID proofing data saved for user
    orcid_authz_success = 'orc.authorization_success'

    # PERSONAL DATA
    # successfully saved personal data
    personal_data_save_success = 'pd.save-success'
    # validation error: missing required field
    personal_data_required = 'pdata.field_required'
    # validation error: illegal characters
    personal_data_special_chars = 'only allow letters'

    # PHONE
    # validation error: not conforming to e164
    phone_personal_data_e164_error = "phone.e164_format"
    # validation error: invalid phone number
    phone_invalid = "phone.phone_format"
    # validation error: invalid swedish number
    phone_swedish_invalid = "phone.swedish_mobile_format"
    # validation error: duplicated phone
    phone_dupe = "phone.phone_duplicated"
    # successfully saved phone number
    phone_save_success = 'phones.save-success'
    # cannot set unconfirmed phone number as primary
    phone_unconfirmed_primary = 'phones.unconfirmed_number_not_primary'
    # successfully set phone number as primary number
    phone_primary_success = 'phones.primary-success'
    # The received verification code is invalid or has expired
    phone_code_invalid = 'phones.code_invalid_or_expired'
    # the received phone to be set as primary is unknown
    phone_unknown_phone = 'phones.unknown_phone'
    # success verifying phone number
    phone_verify_success = 'phones.verification-success'
    # success removing phone number
    phone_removal_success = 'phones.removal-success'
    # success re-sending a verification code
    phone_resend_success = 'phones.code-sent'

    # RESET PASSWORD
    # The user has sent a code that corresponds to no known password reset
    # request
    reset_password_state_not_found = 'resetpw.state-not-found'
    # Some required input data is empty
    reset_password_missing_data = 'resetpw.missing-data'
    # The user has sent an SMS'ed code that corresponds to no known password
    # reset request
    reset_password_unknown_phone_code = 'resetpw.phone-code-unknown'
    # The phone number choice is out of bounds
    reset_password_unknown_phone_number = 'resetpw.phone-number-unknown'
    # The user has sent a code that has expired
    reset_password_expired_email_code = 'resetpw.expired-email-code'
    # The user has sent an SMS'ed code that has expired
    reset_password_expired_phone_code = 'resetpw.expired-phone-code'
    # There was some problem sending the email with the code.
    reset_password_email_send_failure = 'resetpw.email-send-failure'
    # A new code has been generated and sent by email successfully
    reset_password_email_send_throttled = 'resetpw.email-throttled'
    # Sending the email has been throttled.
    reset_password_reset_pw_initialized = 'resetpw.reset-pw-initialized'
    # The password has been successfully reset
    reset_password_pw_reset_success = 'resetpw.pw-reset-success'
    # The password has _NOT_ been successfully reset
    reset_password_pw_reset_fail = 'resetpw.pw-reset-fail'
    # There was some problem sending the SMS with the (extra security) code.
    reset_password_send_sms_throttled = 'resetpw.sms-throttled'
    # Sending the SMS with the (extra security) code has been throttled.
    reset_password_send_sms_failure = 'resetpw.send-sms-failed'
    # A new (extra security) code has been generated and sent by SMS
    # successfully
    reset_password_send_sms_success = 'resetpw.send-sms-success'
    # The phone number has not been verified. Should not happen.
    reset_password_phone_invalid = 'resetpw.phone-invalid'
    # No user was found corresponding to the password reset state. Should not
    # happen.
    reset_password_user_not_found = 'resetpw.user-not-found'
    # The email address has not been verified. Should not happen.
    reset_password_email_not_validated = 'resetpw.email-not-validated'
    # User has not completed signup
    reset_password_invalid_user = 'resetpw.invalid-user'
    # extra security with fido tokens failed - wrong token
    reset_password_fido_token_fail = 'resetpw.fido-token-fail'
    # extra security with external MFA service failed
    reset_password_external_mfa_fail = 'resetpw.external-mfa-fail'
    # The password chosen is too weak
    reset_password_resetpw_weak = 'resetpw.weak-password'

    # SECURITY
    # Too much time passed since re-authn for account termination
    security_stale_reauthn = 'security.stale_authn_info'
    # No reauthn
    security_no_reauthn = 'security.no_reauthn'
    # removing a verified NIN is not allowed
    security_rm_verified = 'nins.verified_no_rm'
    # success removing nin
    security_rm_success = 'nins.success_removal'
    # the user already has the nin
    security_already_exists = 'nins.already_exists'
    # success adding a new nin
    security_add_success = 'nins.successfully_added'
    # The user tried to register more than the allowed number of tokens
    security_max_tokens = 'security.u2f.max_allowed_tokens'
    security_max_webauthn = 'security.webauthn.max_allowed_tokens'
    # missing u2f enrollment data
    security_missing_data = 'security.u2f.missing_enrollment_data'
    # successfully registered u2f token
    security_u2f_registered = 'security.u2f_register_success'
    # No u2f tokens found for the user
    security_no_u2f = 'security.u2f.no_token_found'
    # no challenge data found in session during u2f token verification
    security_no_challenge = 'security.u2f.missing_challenge_data'
    # u2f token not found in user
    security_no_token = 'security.u2f.missing_token'
    # the description provided for the token is too long
    security_long_desc = 'security.u2f.description_to_long'
    # success removing u2f token
    security_rm_u2f_success = 'security.u2f-token-removed'
    # the account has to have personal data to be able to register webauthn data
    security_no_pdata = 'security.webauthn-missing-pdata'
    # success registering webauthn token
    security_webauthn_success = 'security.webauthn_register_success'
    # It is not allowed to remove the last webauthn credential left
    security_no_last = 'security.webauthn-noremove-last'
    # Success removing webauthn token
    security_rm_webauthn = 'security.webauthn-token-removed'
    # token to remove not found
    security_no_webauthn = 'security.webauthn-token-notfound'
    # old_password or new_password missing
    security_chpass_no_data = 'security.change_password_no_data'
    # weak password
    security_chpass_weak = 'security.change_password_weak'
    # wrong old password
    security_unrecognized_pw = 'security.change_password_wrong_old_password'
    # I think these chpass_ values are for the old change-password views (which are still the ones in use)
    security_chpass_password_changed = 'security.change_password_complete'
    security_chpass_password_changed2 = 'chpass.password-changed'

    # SIGNUP
    # the ToU has not been accepted
    signup_no_tou = 'signup.tou-not-accepted'
    # partial success registering new account
    signup_reg_new = 'signup.registering-new'
    # The email address used is already known
    signup_email_used = 'signup.registering-address-used'
    # recaptcha not verified
    signup_no_recaptcha = 'signup.recaptcha-not-verified'
    # unrecognized verification code
    signup_unknown_code = 'signup.unknown-code'
    # the verification code has already been verified
    signup_already_verified = 'signup.already-verified'

    # TEST
    test_fst_test_msg = 'test.first_msg'
    test_snd_test_msg = 'test.second_msg'


@dataclass(frozen=True)
class FluxData:
    status: FluxResponseStatus
    payload: Mapping[str, Any]


def success_response(
    payload: Optional[Mapping[str, Any]] = None, message: Optional[Union[TranslatableMsg, str]] = None
) -> FluxData:
    """
    Make a success response, that can be marshalled into a response that eduid-front understands.

    See the documentation of the MarshalWith decorator for further details on the actual on-the-wire format.

    :param payload: A mapping that will become the Flux Standard Action 'payload'.
                    This should contain data the frontend needs to render a view to the user.
                    For example, in a letter proofing scenario where a user requests that
                    a letter with a code is sent to their registered address, the backend might
                    return the timestamp when a letter was sent, as well as when the code will
                    expire.
    :param message: An optional simple message that will be translated in eduid-front into a message to the user.
                    If used, this should be an TranslatableMsg instance or, for B/C and robustness, a str.
    """
    return FluxData(status=FluxResponseStatus.OK, payload=_make_payload(payload, message, True))


def error_response(
    payload: Optional[Mapping[str, Any]] = None, message: Optional[Union[TranslatableMsg, str]] = None
) -> FluxData:
    """
    Make an error response, that can be marshalled into a response that eduid-front understands.

    See the documentation of the MarshalWith decorator for further details on the actual on-the-wire format.

    :param payload: A mapping that will become the Flux Standard Action 'payload'.
                    This should contain data the frontend needs to render a view to the user.
    :param message: An optional simple message that will be translated in eduid-front into a message to the user.
                    If used, this should be an TranslatableMsg instance or, for B/C and robustness, a str.
    """
    return FluxData(status=FluxResponseStatus.ERROR, payload=_make_payload(payload, message, False))


def _make_payload(
    payload: Optional[Mapping[str, Any]], message: Optional[Union[TranslatableMsg, str]], success: bool
) -> Mapping[str, Any]:
    res: Dict[str, Any] = {}
    if payload is not None:
        res = copy(dict(payload))  # to not mess with callers data

    if message is not None:
        if isinstance(message, TranslatableMsg):
            res['message'] = str(message.value)
        elif isinstance(message, str):
            res['message'] = message
        else:
            raise TypeError('Flux message was neither a TranslatableMsg nor a string')

    # TODO: See if the frontend actually uses this element, and if not - remove it (breaks some tests)
    if 'success' not in res:
        res['success'] = success

    return res


def make_query_string(msg: TranslatableMsg, error: bool = True):
    """
    Make a query string to send a translatable message to the front in the URL of a GET request.

    :param msg: the message to send
    :param error: whether the message is an error message or a success message
    """
    msg_str = str(msg.value)
    if error:
        msg_str = ':ERROR:' + msg_str
    return urlencode({'msg': msg_str})


def redirect_with_msg(url: str, msg: Union[TranslatableMsg, str], error: bool = True) -> WerkzeugResponse:
    """
    :param url: URL to redirect to
    :param msg: message to append to query string
    :param error: Whether it is an error message or not
    :return: Redirect response with appended query string message
    """
    if isinstance(msg, TranslatableMsg):
        msg = str(msg.value)
    if error:
        msg = ':ERROR:' + msg
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_list = parse_qsl(query_string)
    query_list.append(('msg', msg))
    new_query_string = urlencode(query_list)
    return redirect(urlunsplit((scheme, netloc, path, new_query_string, fragment)))
