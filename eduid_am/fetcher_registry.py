"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2019 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
import eduid_am.ams


class AFRegistry(dict):
    '''
    Registry for attribute fetchers.
    When an attribute fetcher is implemented, it opens a connection to the db.
    This should only be done at startup, or at least just once.
    '''
    def __init__(self, config):
        self.conf = config

    def __getitem__(self, key):
        if key not in self:
            af_class = getattr(eduid_am.ams, key, None)
            if af_class is not None:
                self[key] = af_class(self.conf)
            else:
                raise KeyError(f'Trying to fetch attributes from unknown db: {key}')
        return dict.__getitem__(self, key)
