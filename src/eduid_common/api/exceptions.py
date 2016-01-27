# -*- coding: utf-8 -*-

__author__ = 'lundberg'


class ApiException(Exception):
    status_code = 500

    def __init__(self, message='ApiException', status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


class BadConfiguration(Exception):

    def __init__(self, message):
        Exception.__init__(self)
        self.value = message

    def __str__(self):
        return self.value
