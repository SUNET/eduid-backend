# -*- coding = 'utf-8 -*-
__author__ = 'lundberg'

SECRET_KEY = 'supersecretkey'
MONGO_URI = 'mongodb://eduid_authn:eduid_authn_pw@mongodb.eduid_dev'
TESTING = False
SESSION_COOKIE_PATH = '/'
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
PERMANENT_SESSION_LIFETIME = 3600
LOGGER_NAME = 'eduid_webapp.authn'
SERVER_NAME = 'authn.docker:8080'
REDIS_PORT = 6379
REDIS_DB = 0
required_loa = {
    'personal': 'http://www.swamid.se/policy/assurance/al1',
    'helpdesk': 'http://www.swamid.se/policy/assurance/al2',
    'admin': 'http://www.swamid.se/policy/assurance/al3',
}
