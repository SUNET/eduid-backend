from eduid.workers.lookup_mobile.client.mobile_lookup_client import MobileLookupClient
from eduid.workers.lookup_mobile.testing import LookupMobileMongoTestCase


class TestVerifiers(LookupMobileMongoTestCase):
    def test_find_nin_by_mobile(self) -> None:
        # TODO: Actually connects to teleadress?
        from eduid.workers.lookup_mobile.tasks import logger

        mobile_verifier = MobileLookupClient(logger, self.lookup_mobile_settings)

        assert mobile_verifier.find_nin_by_mobile("+46701740610") == "200202027140"
        assert mobile_verifier.find_nin_by_mobile("+46701740608") == "197512126371"
        assert mobile_verifier.find_nin_by_mobile("+46701740609") == "197512126371"
        assert mobile_verifier.find_nin_by_mobile("+46701740699") is None

    def test_find_mobiles_by_nin(self) -> None:
        # TODO: Actually connects to teleadress?
        from eduid.workers.lookup_mobile.tasks import logger

        mobile_verifier = MobileLookupClient(logger, self.lookup_mobile_settings)

        assert mobile_verifier.find_mobiles_by_nin("200202027140") == ["+46701740610"]
        assert mobile_verifier.find_mobiles_by_nin("197512126371") == ["+46701740608", "+46701740609"]
        assert mobile_verifier.find_mobiles_by_nin("46701740699") == []
