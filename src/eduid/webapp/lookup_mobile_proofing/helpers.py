from datetime import datetime
from enum import unique

from eduid.common.rpc.exceptions import LookupMobileTaskFailed
from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.userdb import User
from eduid.userdb.logs import TeleAdressProofing
from eduid.userdb.proofing.element import NinProofingElement
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.util import utc_now
from eduid.webapp.common.api.helpers import check_magic_cookie, get_proofing_log_navet_data
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.lookup_mobile_proofing.app import current_mobilep_app as current_app
from eduid.workers.lookup_mobile.utilities import format_NIN

__author__ = "lundberg"


@unique
class MobileMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # the user has no verified phones to use
    no_phone = "no_phone"
    # problems looking up the phone
    lookup_error = "error_lookup_mobile_task"
    # success verifying the NIN with the phone
    verify_success = "letter.verification_success"
    # no match for the provided phone number
    no_match = "nins.no-mobile-match"


def nin_to_age(nin: str, now: datetime | None = None) -> int:
    """
    :param nin: National Identity Number, YYYYMMDDXXXX
    :return: Age in years
    """
    if now is None:
        now = utc_now()

    born = datetime.strptime(nin[: len("yyyymmdd")], "%Y%m%d")

    age = now.year - born.year - ((now.month, now.day) < (born.month, born.day))

    return age


def create_proofing_state(user: User, nin: str) -> NinProofingState:
    """
    :param user: Central userdb user
    :param nin: National Identity Number
    """
    nin_element = NinProofingElement(number=nin, created_by="lookup_mobile_proofing", is_verified=False)
    return NinProofingState(id=None, modified_ts=None, eppn=user.eppn, nin=nin_element)


def match_mobile_to_user(
    user: User, self_asserted_nin: str, verified_mobile_numbers: list[str]
) -> TeleAdressProofing | None:
    """
    Lookup the user's phone number in the TeleAdress external database. If the phone number comes
    back registered to the self asserted NIN of the user, create a proofing log entry and return it.

    :param user: Any User instance
    :param self_asserted_nin: Self asserted national identity number
    :param verified_mobile_numbers: Verified mobile numbers

    :return: A proofing log entry on success
    """
    # This code is to use the backdoor that allows selenium integration tests
    # to verify a NIN by sending a magic cookie
    if check_magic_cookie(current_app.conf):
        current_app.logger.info("Using the BACKDOOR to verify a NIN through the lookup mobile app")
        user_postal_address = FullPostalAddress(
            **{
                "Name": {"GivenName": "Magic Cookie", "GivenNameMarking": "20", "Surname": "Magic Cookie"},
                "OfficialAddress": {"Address2": "Dummy address", "City": "LANDET", "PostalCode": "12345"},
            }
        )
        proofing_log_entry = TeleAdressProofing(
            eppn=user.eppn,
            created_by="lookup_mobile_proofing",
            reason="magic_cookie",
            nin=self_asserted_nin,
            mobile_number="dummy phone",
            user_postal_address=user_postal_address,
            proofing_version="2014v1",
            deregistration_information=None,
        )
        current_app.stats.count("validate_nin_by_mobile_magic_cookie")
        return proofing_log_entry

    for mobile_number in verified_mobile_numbers:
        try:
            registered_to_nin = current_app.lookup_mobile_relay.find_nin_by_mobile(mobile_number)
            registered_to_nin = format_NIN(registered_to_nin)
            current_app.logger.debug(f"Mobile {mobile_number} registered to NIN: {registered_to_nin}")
        except LookupMobileTaskFailed:
            current_app.logger.error("Lookup mobile task failed for user")
            current_app.logger.debug(f"Mobile number: {mobile_number}")
            raise

        # Check if registered nin was the self asserted nin
        if registered_to_nin == self_asserted_nin:
            current_app.logger.info("Mobile number matched for user")
            current_app.logger.info("Looking up official address for user")
            navet_proofing_data = get_proofing_log_navet_data(nin=self_asserted_nin)
            current_app.logger.info("Creating proofing log entry for user")
            proofing_log_entry = TeleAdressProofing(
                eppn=user.eppn,
                created_by="lookup_mobile_proofing",
                reason="matched",
                nin=self_asserted_nin,
                mobile_number=mobile_number,
                user_postal_address=navet_proofing_data.user_postal_address,
                deregistration_information=navet_proofing_data.deregistration_information,
                proofing_version="2014v1",
            )
            current_app.stats.count("validate_nin_by_mobile_exact_match")
            return proofing_log_entry
        # No match
        else:
            current_app.logger.info(f"Mobile {mobile_number} number NOT matched to users NIN")
            current_app.logger.debug(f"Mobile registered to NIN: {registered_to_nin}")
            current_app.logger.debug(f"User NIN: {self_asserted_nin}")

    # None of the users verified mobile phone numbers matched the NIN
    current_app.stats.count("validate_nin_by_mobile_no_match")
    return None
