from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class EmailMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the requested email is missing
    missing = "emails.missing"
    # the provided email is duplicated
    dupe = "emails.duplicated"
    # success retrieving the account's emails
    get_success = "emails.get-success"
    # A verification mail for that address has been sent recently
    throttled = "emails.throttled"
    still_valid_code = "still-valid-code"
    # The email has been added, but no verification code has been sent (throttled)
    added_and_throttled = "emails.added-and-throttled"
    # succesfully saved new email address
    saved = "emails.save-success"
    # trying to set as primary an unconfirmed address
    unconfirmed_not_primary = "emails.unconfirmed_address_not_primary"
    # success setting email address as primary
    success_primary = "emails.primary-success"
    # the received verification code was invalid or expired
    invalid_code = "emails.code_invalid_or_expired"
    # unknown email received to set as primary
    unknown_email = "emails.unknown_email"
    # success verifying email
    verify_success = "emails.verification-success"
    # it's not allowed to remove all email addresses
    cannot_remove_last = "emails.cannot_remove_unique"
    # it's not allowed to remove all verified email addresses
    cannot_remove_last_verified = "emails.cannot_remove_unique_verified"
    # success removing an email address
    removal_success = "emails.removal-success"
    # success sending a verification code
    code_sent = "emails.code-sent"
