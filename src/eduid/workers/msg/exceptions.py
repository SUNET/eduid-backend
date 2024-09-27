class MessageException(Exception):
    pass


class NavetException(Exception):
    def __init__(self, message: str):
        self.message = message

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"{self.__class__.__name__!s}({self.message!s})"


class NavetAPIException(NavetException):
    pass
