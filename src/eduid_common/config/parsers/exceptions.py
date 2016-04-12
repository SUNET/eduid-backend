# -*- coding: utf-8 -*-
__author__ = 'lundberg'


class ParserException(Exception):

    def __init__(self, message):
        Exception.__init__(self)
        self.value = message

    def __str__(self):
        return self.value
