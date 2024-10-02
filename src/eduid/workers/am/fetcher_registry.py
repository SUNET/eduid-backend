"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2019 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""

from collections.abc import Iterable

import eduid.workers.am.ams
from eduid.workers.am.ams import AttributeFetcher


class AFRegistry:
    """
    Registry for attribute fetchers.
    Attribute fetchers are subclasses of eduid.workers.am.ams.common.AttributeFetcher,
    that have (non pep8) names that coincide with those the different eduid_ apps,
    and reside in eduid.workers.am.ams
    """

    def __init__(self):
        self._fetchers: dict[str, AttributeFetcher] = {}

    def get_fetcher(self, key: str) -> AttributeFetcher:
        if key not in self._fetchers:
            # Dynamically look for a fetcher with that name in the eduid.workers.am.ams module
            af_class = getattr(eduid.workers.am.ams, key, None)
            if af_class is not None:
                from eduid.workers.am.common import AmCelerySingleton

                self.add_fetcher(key, af_class(AmCelerySingleton.worker_config))
            else:
                raise KeyError(f"Trying to fetch attributes from unknown db: {key}")
        return self._fetchers[key]

    def add_fetcher(self, name: str, fetcher: AttributeFetcher) -> None:
        self._fetchers[name] = fetcher

    def all_fetchers(self) -> Iterable[AttributeFetcher]:
        return self._fetchers.values()

    def reset(self) -> None:
        """After a worker failure, we reset the AF registry to have everything re-initialise"""
        self._fetchers = {}
