import unittest
from collections import OrderedDict
from datetime import datetime
from io import BytesIO, StringIO

from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.letter_proofing import pdf
from eduid.webapp.letter_proofing.app import init_letter_proofing_app

# We need to add Navet responses that we fail to handle

__author__ = "lundberg"


class FormatAddressTest(unittest.TestCase):
    def test_successful_format(self):
        navet_responses = [
            OrderedDict(
                [
                    (
                        "Name",
                        OrderedDict(
                            [("GivenNameMarking", "20"), ("GivenName", "Testaren Test"), ("Surname", "Testsson")]
                        ),
                    ),
                    (
                        "OfficialAddress",
                        OrderedDict(
                            [("Address2", "\xd6RGATAN 79 LGH 10"), ("PostalCode", "12345"), ("City", "LANDET")]
                        ),
                    ),
                ]
            ),
            OrderedDict(
                [
                    (
                        "Name",
                        OrderedDict(
                            [
                                ("GivenNameMarking", "20"),
                                ("GivenName", "Testaren Test"),
                                ("MiddleName", "Tester"),
                                ("Surname", "Testsson"),
                            ]
                        ),
                    ),
                    (
                        "OfficialAddress",
                        OrderedDict(
                            [
                                ("Address2", "\xd6RGATAN 79 LGH 10"),
                                ("Address1", "LGH 4321"),
                                ("CareOf", "TESTAREN & TESTSSON"),
                                ("PostalCode", "12345"),
                                ("City", "LANDET"),
                            ]
                        ),
                    ),
                ]
            ),
        ]
        for response in navet_responses:
            name, care_of, address, misc_address, postal_code, city = pdf.format_address(response)
            self.assertIsNotNone(name)
            self.assertIsNotNone(care_of)
            self.assertIsNotNone(address)
            self.assertIsNotNone(misc_address)
            self.assertIsNotNone(postal_code)
            self.assertIsNotNone(city)

    def test_failing_format(self):
        failing_navet_responses = [
            OrderedDict(
                [
                    (
                        "OfficialAddress",
                        OrderedDict(
                            [("Address2", "\xd6RGATAN 79 LGH 10"), ("PostalCode", "12345"), ("City", "LANDET")]
                        ),
                    )
                ]
            ),
            OrderedDict(
                [
                    (
                        "Name",
                        OrderedDict(
                            [("GivenNameMarking", "20"), ("GivenName", "Testaren Test"), ("Surname", "Testsson")]
                        ),
                    ),
                ]
            ),
            OrderedDict(
                [
                    ("Name", OrderedDict([("GivenNameMarking", "20"), ("Surname", "Testsson")])),
                    (
                        "OfficialAddress",
                        OrderedDict(
                            [("Address2", "\xd6RGATAN 79 LGH 10"), ("PostalCode", "12345"), ("City", "LANDET")]
                        ),
                    ),
                ]
            ),
            OrderedDict(
                [
                    ("Name", OrderedDict([("GivenNameMarking", "20"), ("Surname", "Testsson")])),
                    ("OfficialAddress", OrderedDict([("Address2", "\xd6RGATAN 79 LGH 10"), ("City", "LANDET")])),
                ]
            ),
            OrderedDict(
                [
                    (
                        "Name",
                        {
                            "GivenName": "Testaren Test",
                            "MiddleName": "Tester",
                            "GivenNameMarking": "20",
                            "Surname": "Testsson",
                        },
                    ),
                    ("OfficialAddress", {}),
                ]
            ),
        ]

        for response in failing_navet_responses:
            self.assertRaises(pdf.AddressFormatException, pdf.format_address, response)


class CreatePDFTest(EduidAPITestCase):
    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_letter_proofing_app("testing", config)

    def update_config(self, app_config):
        app_config.update(
            {
                "letter_wait_time_hours": 336,
            }
        )
        return app_config

    def test_create_pdf(self):
        recipient = FullPostalAddress.parse_obj(
            OrderedDict(
                [
                    (
                        "Name",
                        OrderedDict(
                            [
                                ("GivenNameMarking", "20"),
                                ("GivenName", "Testaren Test"),
                                ("MiddleName", "Tester"),
                                ("Surname", "Testsson"),
                            ]
                        ),
                    ),
                    (
                        "OfficialAddress",
                        OrderedDict(
                            [
                                ("Address2", "\xd6RGATAN 79 LGH 10"),
                                ("Address1", "LGH 4321"),
                                ("CareOf", "TESTAREN & TESTSSON"),
                                ("PostalCode", "12345"),
                                ("City", "LANDET"),
                            ]
                        ),
                    ),
                ]
            )
        )

        with self.app.app_context():
            with self.app.test_request_context():
                pdf_document = pdf.create_pdf(
                    recipient,
                    verification_code="bogus code",
                    created_timestamp=datetime.utcnow(),
                    primary_mail_address="test@example.org",
                    letter_wait_time_hours=336,
                )
        self.assertIsInstance(pdf_document, (StringIO, BytesIO))
