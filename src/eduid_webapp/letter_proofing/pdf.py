# -*- coding: utf-8 -*-

from __future__ import absolute_import

from datetime import timedelta

from six import BytesIO, StringIO
from xhtml2pdf import pisa

from eduid_webapp.letter_proofing.app import current_letterp_app as current_app


class AddressFormatException(Exception):
    pass


def format_address(recipient):
    """
    :param recipient: official address
    :type recipient: OrderedDict
    :return: name, address, postal code
    :rtype: tuple
    """
    try:
        # TODO: Take GivenNameMarking in to account
        given_name = recipient.get('Name')['GivenName']  # Mandatory
        middle_name = recipient.get('Name').get('MiddleName', '')  # Optional
        surname = recipient.get('Name')['Surname']  # Mandatory
        name = u'{!s} {!s} {!s}'.format(given_name, middle_name, surname)
        # TODO: Take eventual CareOf and Address1(?) in to account
        care_of = recipient.get('OfficialAddress').get('CareOf', '')  # Optional
        address = recipient.get('OfficialAddress')['Address2']  # Mandatory
        # From Skatteverket's documentation it is not clear why Address1
        # is needed. In practice it is rarely used, but when actually
        # used it has been seen to often contains apartment numbers.
        misc_address = recipient.get('OfficialAddress').get('Address1', '')  # Optional
        postal_code = recipient.get('OfficialAddress')['PostalCode']  # Mandatory
        city = recipient.get('OfficialAddress')['City']  # Mandatory
        return name, care_of, address, misc_address, postal_code, city
    except (KeyError, TypeError, AttributeError) as e:
        raise AddressFormatException(e)


def create_pdf(recipient, verification_code, created_timestamp, primary_mail_address):
    """
    Create a letter in the form of a PDF-document,
    containing a verification code to be sent to a user.

    :param recipient: Official address the letter should be sent to
    :param verification_code: Verification code to include in the letter
    :param created_timestamp: Timestamp for when the proofing was initiated
    :param primary_mail_address The users primary mail address
    """
    # Imported here to avoid exposing
    # render_template to the calling function.
    from flask import render_template

    pisa.showLogging()

    try:
        name, care_of, address, misc_address, postal_code, city = format_address(recipient)
    except AddressFormatException as e:
        current_app.logger.error('Postal address formatting failed: {!r}'.format(e))
        raise e

    # Calculate the validity period of the verification
    # code that is to be shown in the letter.
    max_wait = timedelta(hours=current_app.config.letter_wait_time_hours)
    validity_period = (created_timestamp + max_wait).strftime('%Y-%m-%d')

    letter_template = render_template(
        'letter.html',
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
