# -*- coding: utf-8 -*-

from __future__ import absolute_import

import unittest
from collections import OrderedDict
from datetime import datetime
from six import StringIO, BytesIO
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.letter_proofing.app import init_letter_proofing_app
from eduid_webapp.letter_proofing import pdf

# We need to add Navet responses that we fail to handle

__author__ = 'lundberg'


class FormatAddressTest(unittest.TestCase):

    def test_successful_format(self):

        navet_responses = [
            OrderedDict([
                (u'Name', OrderedDict([
                    (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                    (u'Surname', u'Testsson')])),
                (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                                  (u'PostalCode', u'12345'),
                                                  (u'City', u'LANDET')]))
            ]),
            OrderedDict([
                (u'Name', OrderedDict([
                    (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                    (u'MiddleName', u'Tester'), (u'Surname', u'Testsson')])),
                (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                                  (u'Address1', u'LGH 4321'),
                                                  (u'CareOf', u'TESTAREN & TESTSSON'),
                                                  (u'PostalCode', u'12345'),
                                                  (u'City', u'LANDET')]))
            ])
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
            OrderedDict([
                (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                                  (u'PostalCode', u'12345'),
                                                  (u'City', u'LANDET')]))
            ]),
            OrderedDict([
                (u'Name', OrderedDict([
                    (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                    (u'Surname', u'Testsson')])),
            ]),
            OrderedDict([
                (u'Name', OrderedDict([
                    (u'GivenNameMarking', u'20'), (u'Surname', u'Testsson')])),
                (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                                  (u'PostalCode', u'12345'),
                                                  (u'City', u'LANDET')]))
            ]),
            OrderedDict([
                (u'Name', OrderedDict([
                    (u'GivenNameMarking', u'20'), (u'Surname', u'Testsson')])),
                (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                                  (u'City', u'LANDET')]))
            ]),
            OrderedDict([
                (u'Name',
                 {u'GivenName': u'Testaren Test',
                  u'MiddleName': u'Tester',
                  u'GivenNameMarking': u'20',
                  u'Surname': u'Testsson'}),
                (u'OfficialAddress', {})])
        ]

        for response in failing_navet_responses:
            self.assertRaises(pdf.AddressFormatException, pdf.format_address, response)


class CreatePDFTest(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_letter_proofing_app('testing', config)

    def update_config(self, config):
        config.update({
            'LETTER_WAIT_TIME_HOURS': 336,
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
        })
        return config

    def test_create_pdf(self):

        recipient = OrderedDict([
                (u'Name', OrderedDict([
                    (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                    (u'MiddleName', u'Tester'), (u'Surname', u'Testsson')])),
                (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                                  (u'Address1', u'LGH 4321'),
                                                  (u'CareOf', u'TESTAREN & TESTSSON'),
                                                  (u'PostalCode', u'12345'),
                                                  (u'City', u'LANDET')]))
            ])

        with self.app.app_context():
            pdf_document = pdf.create_pdf(recipient, verification_code='bogus code',
                                          created_timestamp=datetime.utcnow(), primary_mail_address='test@example.org')
            self.assertIsInstance(pdf_document, (StringIO, BytesIO))
