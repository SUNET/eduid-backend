# -*- coding: utf-8 -*-

__author__ = "lundberg"


class EduIDGroupDBError(Exception):
    pass


class VersionMismatch(EduIDGroupDBError):
    pass


class MultipleReturnedError(EduIDGroupDBError):
    pass


class MultipleUsersReturned(MultipleReturnedError):
    pass


class MultipleGroupsReturned(MultipleReturnedError):
    pass
