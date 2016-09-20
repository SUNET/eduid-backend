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
LOG_FILE = None
LOG_LEVEL = 'INFO'

# letter_proofing
LETTER_WAIT_TIME_HOURS = 336  # 2 weeks

EKOPOST_API_URI = 'https://api.ekopost.se'
EKOPOST_API_VERIFY_SSL = 'true'
EKOPOST_API_USER = ''
EKOPOST_API_PW = ''
EKOPOST_DEBUG_PDF = ''

