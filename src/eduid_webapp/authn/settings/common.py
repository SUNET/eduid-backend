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

IMPLICIT_LOGIN_SUCCESS_REDIRECT_URL = "https://dashboard.eduid.se"
IMPLICIT_LOGIN_FAILURE_REDIRECT_URL = "https://dashboard.eduid.se"
