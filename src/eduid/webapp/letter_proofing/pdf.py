import logging
from collections.abc import Mapping
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from pathlib import Path

from xhtml2pdf import pisa

from eduid.common.proofing_utils import get_marked_given_name
from eduid.common.rpc.msg_relay import FullPostalAddress

logger = logging.getLogger(__name__)


class AddressFormatException(Exception):
    pass


def format_address(recipient: Mapping) -> tuple:
    """
    :param recipient: official address
    :type recipient: OrderedDict
    :return: name, address, postal code
    :rtype: tuple
    """
    try:
        _notification_name = recipient.get("Name", {}).get("NotificationName", None)  # Optional
        if _notification_name:
            name = _notification_name
        else:
            _given_name_marking = recipient.get("Name", {}).get("GivenNameMarking", None)  # Optional
            _given_name = recipient.get("Name", {})["GivenName"]  # Mandatory
            given_name = get_marked_given_name(_given_name, _given_name_marking)
            middle_name = recipient.get("Name", {}).get("MiddleName", "")  # Optional
            surname = recipient.get("Name", {})["Surname"]  # Mandatory
            name = f"{given_name!s} {middle_name!s} {surname!s}"
        # TODO: Take eventual CareOf and Address1(?) in to account
        care_of = recipient.get("OfficialAddress", {}).get("CareOf", "")  # Optional
        address = recipient.get("OfficialAddress", {})["Address2"]  # Mandatory
        # From Skatteverket's documentation it is not clear why Address1
        # is needed. In practice it is rarely used, but when actually
        # used it has been seen to often contains apartment numbers.
        misc_address = recipient.get("OfficialAddress", {}).get("Address1", "")  # Optional
        postal_code = recipient.get("OfficialAddress", {})["PostalCode"]  # Mandatory
        city = recipient.get("OfficialAddress", {})["City"]  # Mandatory
        return name, care_of, address, misc_address, postal_code, city
    except (KeyError, TypeError, AttributeError) as e:
        raise AddressFormatException(e) from e


def create_pdf(
    recipient: FullPostalAddress,
    verification_code: str,
    created_timestamp: datetime,
    primary_mail_address: str,
    letter_wait_time_hours: int,
) -> BytesIO:
    """
    Create a letter in the form of a PDF-document,
    containing a verification code to be sent to a user.

    :param recipient: Official address the letter should be sent to
    :param verification_code: Verification code to include in the letter
    :param created_timestamp: Timestamp for when the proofing was initiated
    :param primary_mail_address: The users primary mail address
    :param letter_wait_time_hours: The expire time for the code
    """
    # Imported here to avoid exposing
    # render_template to the calling function.
    from flask import render_template

    pisa.showLogging()

    try:
        name, care_of, address, misc_address, postal_code, city = format_address(
            recipient.model_dump(exclude_none=True, by_alias=True)
        )
    except AddressFormatException as e:
        logger.error(f"Postal address formatting failed: {e!r}")
        raise e

    # Calculate the validity period of the verification
    # code that is to be shown in the letter.
    max_wait = timedelta(hours=letter_wait_time_hours)
    validity_period = (created_timestamp + max_wait).strftime("%Y-%m-%d")
    templates_path = Path(__file__).with_name("templates")

    letter_template = render_template(
        "letter.jinja2",
        sunet_logo=f"{templates_path}/sunet_logo.eps",
        recipient_name=name,
        recipient_care_of=care_of,
        recipient_address=address,
        recipient_misc_address=misc_address,
        recipient_postal_code=postal_code,
        recipient_city=city,
        recipient_verification_code=verification_code,
        recipient_validity_period=validity_period,
        recipient_primary_mail_address=primary_mail_address,
    )

    pdf_document = BytesIO()
    pisa.CreatePDF(StringIO(letter_template), pdf_document)
    return pdf_document
