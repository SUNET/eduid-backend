from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class PhoneMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # captcha not completed
    captcha_not_completed = "phone.captcha-not-completed"
    # captcha completion failed
    captcha_failed = "phone.captcha-failed"
    # captcha already completed
    captcha_already_completed = "phone.captcha-already-completed"
    # captcha not requested from get-captcha endpoint
    captcha_not_requested = "phone.captcha-not-requested"
    # validation error: not conforming to e164
    e164_error = "phone.e164_format"
    # validation error: invalid phone number
    phone_invalid = "phone.phone_format"
    # validation error: invalid swedish number
    swedish_invalid = "phone.swedish_mobile_format"
    # validation error: duplicated phone
    dupe = "phone.phone_duplicated"
    # successfully saved phone number
    save_success = "phones.save-success"
    # cannot set unconfirmed phone number as primary
    unconfirmed_primary = "phones.unconfirmed_number_not_primary"
    # successfully set phone number as primary number
    primary_success = "phones.primary-success"
    # The received verification code is invalid or has expired
    code_invalid = "phones.code_invalid_or_expired"
    # the received phone to be set as primary is unknown
    unknown_phone = "phones.unknown_phone"
    # success verifying phone number
    verify_success = "phones.verification-success"
    # success removing phone number
    removal_success = "phones.removal-success"
    # the previously sent verification code is still valid
    still_valid_code = "still-valid-code"
    # success re-sending a verification code
    send_code_success = "phones.code-sent"
