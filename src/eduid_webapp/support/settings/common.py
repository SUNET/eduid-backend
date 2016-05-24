# -*- coding: utf-8 -*-

from __future__ import absolute_import

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

# Secret key
SECRET_KEY = '123456'

# Logging
LOG_FILE = None
LOG_LEVEL = 'INFO'

# Support
SUPPORT_PERSONNEL = ['']
