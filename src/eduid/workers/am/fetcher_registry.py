"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2019 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
import eduid.workers.am.ams


class AFRegistry(dict):
    '''
    Registry for attribute fetchers.
    Attribute fetchers are subclasses of eduid.workers.am.ams.common.AttributeFetcher,
    that have (non pep8) names that coincide with those the different eduid_ apps,
    and reside in eduid.workers.am.ams
    '''

    def __getitem__(self, key: str):
        if key not in self:
            af_class = getattr(eduid.workers.am.ams, key, None)
            if af_class is not None:
                from eduid.workers.am.common import AmWorkerSingleton

                self[key] = af_class(AmWorkerSingleton.am_config)
            else:
                raise KeyError(f'Trying to fetch attributes from unknown db: {key}')
        return dict.__getitem__(self, key)
