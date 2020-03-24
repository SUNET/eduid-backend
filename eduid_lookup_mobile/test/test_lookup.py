from eduid_lookup_mobile.client.mobile_lookup_client import MobileLookupClient
from eduid_lookup_mobile.testing import LookupMobileMongoTestCase


class TestVerifiers(LookupMobileMongoTestCase):
    def setUp(self):
        super(TestVerifiers, self).setUp()

    def test_find_NIN_by_mobile(self):
        from eduid_lookup_mobile.tasks import logger

        mobile_verifier = MobileLookupClient(logger, self.lookup_mobile_settings)

        self.assertEqual(mobile_verifier.find_NIN_by_mobile('+46700011222'), '200202027140')
        self.assertEqual(mobile_verifier.find_NIN_by_mobile('+46700011333'), '197512126371')
        self.assertEqual(mobile_verifier.find_NIN_by_mobile('+46700011777'), '197512126371')
        self.assertEqual(mobile_verifier.find_NIN_by_mobile('+46700011999'), None)

    def test_find_mobiles_by_NIN(self):
        from eduid_lookup_mobile.tasks import logger

        mobile_verifier = MobileLookupClient(logger, self.lookup_mobile_settings)

        self.assertEqual(mobile_verifier.find_mobiles_by_NIN('200202027140'), ['+46700011222'])
        self.assertEqual(mobile_verifier.find_mobiles_by_NIN('197512126371'), ['+46700011333', '+46700011777'])
        self.assertEqual(mobile_verifier.find_mobiles_by_NIN('197512125430'), [])
