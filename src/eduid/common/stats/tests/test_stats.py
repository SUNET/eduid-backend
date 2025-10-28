import unittest

from eduid.common.config.base import StatsConfigMixin
from eduid.common.stats import init_app_stats

__author__ = "lundberg"


class StatsTests(unittest.TestCase):
    def setUp(self) -> None:
        stats_config = StatsConfigMixin(app_name="test")
        self.stats = init_app_stats(stats_config)

    def test_clean_name_url(self) -> None:
        name = "https://example.org/some/endpoint"
        name = self.stats.clean_name(name)
        assert name == "https--example.org-some-endpoint"
