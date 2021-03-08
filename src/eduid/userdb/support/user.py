# -*- coding: utf-8 -*-
from dataclasses import dataclass

from eduid_userdb.signup import SignupUser
from eduid_userdb.user import User

__author__ = 'lundberg'


@dataclass
class SupportUser(User):
    pass


@dataclass
class SupportSignupUser(SignupUser):
    pass
