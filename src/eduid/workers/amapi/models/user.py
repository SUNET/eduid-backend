from curses.ascii import US
from typing import Any, Dict, List, Mapping, Optional

from pydantic import Field

from eduid.userdb import User

__author__ = 'masv'


class UserUpdateResponse:
    pass


class UserUpdateNameRequest(User):
    @staticmethod
    def operation() -> Mapping[str, Any]:
        unsets = {}
        sets = {}

        if User.given_name is None:
            unsets["given_name"]
        if User.given_name is not None:
            sets['given_name'] = User.given_name
        if User.surname is None:
            unsets['surname']
        if User.surname is not None:
            sets['surname'] = User.surname

        operations = {
            '$unset': unsets,
            '$set': sets,
        }
        return operations


class UserUpdateEmailRequest(User):
    @staticmethod
    def operation() -> Mapping[str, Any]:
        unsets = {}
        sets = {}

        if User.mail_addresses is None:
            unsets['mail_addresses']
        if User.mail_addresses is not None:
            sets['mail_addresses'] = User.mail_addresses

        operations = {
            '$unset': unsets,
            '$set': sets,
        }
        return operations


class UserCreateRequest(User):
    pass


class UserResponse:
    pass
