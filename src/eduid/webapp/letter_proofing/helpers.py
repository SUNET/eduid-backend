from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import unique

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.common.utils import get_short_hash
from eduid.userdb import User
from eduid.userdb.proofing import LetterProofingState, NinProofingElement
from eduid.userdb.proofing.element import SentLetterElement
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.letter_proofing import pdf
from eduid.webapp.letter_proofing.app import current_letterp_app as current_app

__author__ = "lundberg"


@unique
class LetterMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # No letter proofing state found in the db
    no_state = "letter.no_state_found"
    # a letter has already been sent
    already_sent = "letter.already-sent"
    # the letter has been sent, but enough time has passed to send a new one
    letter_expired = "letter.expired"
    # some unspecified problem sending the letter
    not_sent = "letter.not-sent"
    # no postal address found
    address_not_found = "letter.no-address-found"
    # errors in the format of the postal address
    bad_address = "letter.bad-postal-address"
    # letter sent and state saved w/o errors
    letter_sent = "letter.saved-unconfirmed"
    # wrong verification code received
    wrong_code = "letter.wrong-code"
    # success verifying the code
    verify_success = "letter.verification_success"


@dataclass
class StateExpireInfo:
    sent: datetime
    expires: datetime
    is_expired: bool
    error: bool
    message: TranslatableMsg

    def to_response(self) -> FluxData:
        """Create a response with information about the users current proofing state (or an error)."""
        if self.error:
            return error_response(message=self.message)
        res = {
            "letter_sent": self.sent,
            "letter_expires": self.expires,
            "letter_expired": self.is_expired,
        }
        now = utc_now()

        # If a letter was sent yesterday, letter_sent_days_ago should be 1 even if it
        # is now one minute past midnight and the letter was sent two minutes ago
        _delta = now - self.sent.replace(hour=0, minute=0, second=1)
        res["letter_sent_days_ago"] = _delta.days

        if self.expires and not self.is_expired:
            _delta = self.expires - now
            res["letter_expires_in_days"] = _delta.days

        return success_response(res, message=self.message)


def check_state(state: LetterProofingState) -> StateExpireInfo:
    """
    Checks if the state is expired.

    :param state: Users proofing state
    :return: Information about the users current letter proofing state,
             such as when it was created, when it expires etc.
    """
    current_app.logger.info(f"Checking state for user with eppn {state.eppn!s}")
    if not state.proofing_letter.is_sent:
        current_app.logger.info(f"Unfinished state for user with eppn {state.eppn!s}")
        current_app.logger.debug(f"Proofing state: {state.to_dict()}")
        # need a datetime for typing, but sent/expires/is_expired are not included in error responses
        _fake_dt = datetime.fromtimestamp(0)
        return StateExpireInfo(sent=_fake_dt, expires=_fake_dt, is_expired=True, error=True, message=LetterMsg.not_sent)

    current_app.logger.info(f"Letter is sent for user with eppn {state.eppn!s}")
    # Check how long ago the letter was sent
    sent_dt = state.proofing_letter.sent_ts
    if not isinstance(sent_dt, datetime):
        raise ValueError("SentLetterElement must have a datetime sent_ts attr if is_sent is True")

    expires_at = sent_dt + timedelta(hours=current_app.conf.letter_wait_time_hours)
    # Give the user until midnight the day the code expires
    expires_at = expires_at.replace(hour=23, minute=59, second=59)

    now = utc_now()
    if now < expires_at:
        current_app.logger.info(f"User with eppn {state.eppn} has to wait for letter to arrive.")
        current_app.logger.info(f"Code expires: {expires_at}")
        # The user has to wait for the letter to arrive
        return StateExpireInfo(
            sent=sent_dt, expires=expires_at, is_expired=False, error=False, message=LetterMsg.already_sent
        )
    else:
        current_app.logger.info(f"Letter expired for user with eppn {state.eppn!s}.")
        return StateExpireInfo(
            sent=sent_dt, expires=expires_at, is_expired=True, error=False, message=LetterMsg.letter_expired
        )


def create_proofing_state(eppn: str, nin: str) -> LetterProofingState:
    _nin = NinProofingElement(
        number=nin,
        created_by="eduid-idproofing-letter",
        is_verified=False,
        verification_code=get_short_hash(),
    )
    proofing_letter = SentLetterElement()
    proofing_state = LetterProofingState(
        eppn=eppn, nin=_nin, proofing_letter=proofing_letter, id=None, modified_ts=None
    )
    current_app.logger.debug(f"Created proofing state: {proofing_state.to_dict()}")
    return proofing_state


def get_address(user: User, proofing_state: LetterProofingState) -> FullPostalAddress:
    """
    :param user: User object
    :param proofing_state: Users proofing state

    Example result:

      {'Name': {'GivenName': 'First', 'Surname': 'Last'}, 'OfficialAddress': { ... }}

    If the individual doesn't have a registered address, the OfficialAddress dict is (might be?) empty.

    :return: Users official postal address
    """
    current_app.logger.info(f"Getting address for user {user}")
    current_app.logger.debug(f"NIN: {proofing_state.nin.number!s}")
    if check_magic_cookie(current_app.conf):
        # return bogus data without Navet interaction for integration test
        current_app.logger.info("Using magic cookie to get address")
        return FullPostalAddress(
            Name={"GivenNameMarking": "20", "GivenName": "Magic Cookie", "Surname": "Testsson"},
            OfficialAddress={"Address2": "MAGIC COOKIE", "PostalCode": "12345", "City": "LANDET"},
        )
    # Lookup official address via Navet
    address = current_app.msg_relay.get_postal_address(proofing_state.nin.number)
    current_app.logger.debug(f"Official address: {address!r}")
    return address


def send_letter(user: User, proofing_state: LetterProofingState) -> str:
    """
    :param user: User object
    :param proofing_state: Users proofing state

    :return: Transaction id
    """
    if not proofing_state.proofing_letter.address:
        raise ValueError("No address in proofing_state")
    if not proofing_state.nin.verification_code:
        raise ValueError("No verification_code in proofing_state")
    if not user.mail_addresses.primary:
        raise RuntimeError("User has no primary e-mail address")
    # Create the letter as a PDF-document and send it to our letter sender service
    pdf_letter = pdf.create_pdf(
        recipient=proofing_state.proofing_letter.address,
        verification_code=proofing_state.nin.verification_code,
        created_timestamp=proofing_state.nin.created_ts,
        primary_mail_address=user.mail_addresses.primary.email,
        letter_wait_time_hours=current_app.conf.letter_wait_time_hours,
    )
    if current_app.conf.ekopost_debug_pdf_path is not None:
        # Write PDF to file instead of actually sending it if ekopost_debug_pdf_path is set
        with open(current_app.conf.ekopost_debug_pdf_path, "wb") as fd:
            fd.write(pdf_letter.getvalue())
        return "debug mode transaction id"
    campaign_id = current_app.ekopost.send(user.eppn, pdf_letter)
    return campaign_id
