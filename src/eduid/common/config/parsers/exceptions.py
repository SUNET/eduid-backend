__author__ = "lundberg"


class ParserException(Exception):
    def __init__(self, message: str):
        Exception.__init__(self)
        self.value = message

    def __str__(self):
        return self.value


class SecretKeyException(ParserException):
    pass
