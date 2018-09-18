# -*- coding: utf-8 -*-

from __future__ import absolute_import


__author__ = 'lundberg'

"""
For more built in configuration options see,
http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values
"""

DEBUG = False

# Database URIs
MONGO_URI = ''
REDIS_HOST = ''
REDIS_PORT = 6379
REDIS_DB = 0

# Celery config
AM_BROKER_URL = ''
MSG_BROKER_URL = ''
CELERY_CONFIG = {
    'CELERY_RESULT_BACKEND': 'amqp',
    'CELERY_TASK_SERIALIZER': 'json'
}

# Secret key
SECRET_KEY = None

# Logging
LOG_LEVEL = 'INFO'

# Federation config
AUTHENTICATION_CONTEXT_MAP = {
    'loa1': 'http://id.elegnamnden.se/loa/1.0/loa1',
    'loa2': 'http://id.elegnamnden.se/loa/1.0/loa2',
    'loa3': 'http://id.elegnamnden.se/loa/1.0/loa3',
    'uncertified-loa3': 'http://id.swedenconnect.se/loa/1.0/uncertified-loa3',
    'loa4': 'http://id.elegnamnden.se/loa/1.0/loa4',
    'eidas-low': 'http://id.elegnamnden.se/loa/1.0/eidas-low',
    'eidas-sub': 'http://id.elegnamnden.se/loa/1.0/eidas-sub',
    'eidas-high': 'http://id.elegnamnden.se/loa/1.0/eidas-high',
    'eidas-nf-low': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-low',
    'eidas-nf-sub': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-sub',
    'eidas-nf-high': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-high'
}
