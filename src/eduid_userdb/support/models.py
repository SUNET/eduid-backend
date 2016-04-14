# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_userdb.user import User
from eduid_userdb.dashboard.user import DashboardUser
from eduid_userdb.signup.user import SignupUser

__author__ = 'lundberg'


class SupportUser(User):
    pass


class SupportDashboardUser(DashboardUser):
    pass


class SupportSignupUser(SignupUser):
    pass

