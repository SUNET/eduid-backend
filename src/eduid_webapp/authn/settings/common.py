# -*- coding: utf-8 -*-
__author__ = 'lundberg'

SERVER_NAME = ''
SECRET_KEY = ''
MONGO_URI = 'mongodb://'
REDIS_HOST = ''


required_loa = {
    'personal': 'http://www.swamid.se/policy/assurance/al1',
    'helpdesk': 'http://www.swamid.se/policy/assurance/al2',
    'admin': 'http://www.swamid.se/policy/assurance/al3',
}  # Should be changed to uppercase

SIGNUP_AND_AUTHN_SHARED_KEY = None
TOKEN_LOGIN_SUCCESS_REDIRECT_URL = "https://dashboard.eduid.se"
TOKEN_LOGIN_FAILURE_REDIRECT_URL = "https://dashboard.eduid.se"
