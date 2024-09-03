"""
The eduID User Database interface package.

Copyright (c) 2013-2017 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""

__version__ = "0.0.1"
__copyright__ = "SUNET"
__organization__ = "SUNET"
__license__ = "BSD"
__authors__ = ["Fredrik Thulin"]

from eduid.userdb.db import MongoDB
from eduid.userdb.event import EventList
from eduid.userdb.identity import EIDASIdentity, NinIdentity, SvipeIdentity
from eduid.userdb.locked_identity import LockedIdentityList
from eduid.userdb.mail import MailAddress
from eduid.userdb.nin import Nin
from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.phone import PhoneNumber
from eduid.userdb.profile import Profile
from eduid.userdb.tou import ToUEvent
from eduid.userdb.user import User
from eduid.userdb.userdb import AmDB, UserDB

__all__ = [
    'User',
    'UserDB',
    'AmDB',
    'EventList',
    'ToUEvent',
    'Profile',
    'Nin',
    'NinIdentity',
    'SvipeIdentity',
    'EIDASIdentity',
    'MailAddress',
    'PhoneNumber',
    'OidcIdToken',
    'OidcAuthorization',
    'Orcid',
    'LockedIdentityList',
    'MongoDB',
]