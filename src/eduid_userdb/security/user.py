# -*- coding: utf-8 -*-
from __future__ import absolute_import

from dataclasses import dataclass

from eduid_userdb.user import User

__author__ = 'lundberg'


@dataclass
class SecurityUser(User):
    pass
