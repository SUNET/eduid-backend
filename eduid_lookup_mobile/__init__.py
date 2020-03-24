"""
eduID Lookup Mobile package.

Copyright (c) 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from __future__ import absolute_import

from eduid_common.rpc.celery import init_celery as _init_celery

import eduid_lookup_mobile.common as common


def init_app(config):
    common.celery = _init_celery('eduid_lookup_mobile', config)
    return common.celery
