class MessageException(Exception):
    pass


class NavetException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return "{!s}({!s})".format(self.__class__.__name__, self.message)


class NavetAPIException(NavetException):
    pass
