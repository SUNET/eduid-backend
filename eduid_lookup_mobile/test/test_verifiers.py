from unittest import TestCase
from eduid_lookup_mobile.client.mobile_lookup_client import MobileLookupClient


class TestVerifiers(TestCase):

    def test_verify_mobile(self):
        """
        mobile_verifier = MobileLookupClient()

        self.assertTrue(mobile_verifier.verify_by_NIN('', ''),
                        'The phone number and SSNo should give a positive verification')
        """