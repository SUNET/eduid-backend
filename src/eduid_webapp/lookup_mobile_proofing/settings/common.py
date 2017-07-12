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
LOOKUP_MOBILE_BROKER_URL = ''
CELERY_CONFIG = {
    'CELERY_RESULT_BACKEND': 'amqp',
    'CELERY_TASK_SERIALIZER': 'json',
}

# Secret key
SECRET_KEY = None

# Logging
LOG_FILE = None
LOG_LEVEL = 'INFO'
