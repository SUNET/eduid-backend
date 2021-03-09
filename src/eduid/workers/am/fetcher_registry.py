"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2019 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from typing import Optional

import eduid.workers.am.ams
from eduid.common.config.workers import AmConfig


class AFRegistry(dict):
    '''
    Registry for attribute fetchers.
    Attribute fetchers are subclasses of eduid.workers.am.ams.common.AttributeFetcher,
    that have (non pep8) names that coincide with those the different eduid_ apps,
    and reside in eduid.workers.am.ams
    '''

    def __init__(self, config: Optional[AmConfig] = None):
        super().__init__()

        if not config:
            import eduid.workers.am.worker

            config = eduid.workers.am.worker.worker_config
        self.conf = config

    def __getitem__(self, key: str):
        if key not in self:
            af_class = getattr(eduid.workers.am.ams, key, None)
            if af_class is not None:
                self[key] = af_class(self.conf)
            else:
                raise KeyError(f'Trying to fetch attributes from unknown db: {key}')
        return dict.__getitem__(self, key)
