# -*- coding: utf-8 -*-

from __future__ import absolute_import

from os.path import abspath, dirname, join, normpath
from apispec import APISpec

__author__ = 'lundberg'

DEBUG = True

# Absolute filesystem path to the Flask project directory:
APP_ROOT = dirname(dirname(abspath(__file__)))

# Absolute filesystem path to the secret file which holds this project's
# SECRET_KEY. Will be auto-generated the first time this file is interpreted.
SECRET_FILE = normpath(join(APP_ROOT, 'SECRET'))

# Try to load the SECRET_KEY from our SECRET_FILE. If that fails, then generate
# a random SECRET_KEY and save it into our SECRET_FILE for future loading. If
# everything fails, then just raise an exception.
try:
    SECRET_KEY = open(SECRET_FILE).read().strip()
except IOError:
    try:
        with open(SECRET_FILE, 'w') as f:
            import random
            choice = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
            SECRET_KEY = ''.join([random.SystemRandom().choice(choice) for i in range(50)])
            f.write(SECRET_KEY)
    except IOError:
        raise Exception('Cannot open file `%s` for writing.' % SECRET_FILE)

MONGO_URI = 'mongodb://eduid_idproofing_letter:eduid_idproofing_letter_pw@mongodb.docker'
REDIS_HOST = 'redis.docker'

LOG_FILE = join(APP_ROOT, 'logs/oidc_proofing.log')
LOG_LEVEL = 'DEBUG'

APISPEC_SPEC = APISpec(
    title='eduid-oidc-proofing',
    version='v1',
    plugins=('apispec.ext.marshmallow',),
)
