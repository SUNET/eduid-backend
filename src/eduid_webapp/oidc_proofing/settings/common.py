# -*- coding: utf-8 -*-

from __future__ import absolute_import


__author__ = 'lundberg'

"""
For more built in configuration options see,
http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values
"""

DEBUG = False

# Database URIs
MONGO_URI = 'mongodb://'
REDIS_HOST = ''
REDIS_PORT = 6379
REDIS_DB = 0

# Celery config
AM_BROKER_URL = ''
CELERY_CONFIG = {
    'CELERY_RESULT_BACKEND': 'amqp',
    'CELERY_TASK_SERIALIZER': 'json'
}

# Secret key
SECRET_KEY = None

# Logging
LOG_LEVEL = 'INFO'

# OIDC
CLIENT_REGISTRATION_INFO = {
    'client_id': 'can_not_be_empty_string',
    'client_secret': ''
}

PROVIDER_CONFIGURATION_INFO = {
    'issuer': 'can_not_be_empty_string',
    'authorization_endpoint': '',
    'jwks_uri': '',
    'response_types_supported': '',
    'subject_types_supported': '',
    'id_token_signing_alg_values_supported': '',

}
USERINFO_ENDPOINT_METHOD = 'POST'

# Freja config
FREJA_JWS_ALGORITHM = 'HS256'
FREJA_JWS_KEY_ID = ''
FREJA_JWK_SECRET = ''  # secret in hex
FREJA_IARP = ''  # Relying party identity
FREJA_EXPIRE_TIME_HOURS = 336  # 2 weeks, needs minimum 5 minutes and maximum 60 days
FREJA_RESPONSE_PROTOCOL = '1.0'  # Version

# SE-LEG config
SELEG_EXPIRE_TIME_HOURS = 336  # Needs to be the same as FREJA_EXPIRE_TIME_HOURS as state is shared
