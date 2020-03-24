"""
The eduID User Database interface package.

Copyright (c) 2013-2017 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""


__version__ = '0.0.1'
__copyright__ = 'SUNET'
__organization__ = 'SUNET'
__license__ = 'BSD'
__authors__ = ['Fredrik Thulin']

import eduid_userdb.exceptions
import eduid_userdb.mail
import eduid_userdb.phone
from eduid_userdb.db import MongoDB
from eduid_userdb.event import EventList
from eduid_userdb.locked_identity import LockedIdentityNin
from eduid_userdb.mail import MailAddress
from eduid_userdb.nin import Nin
from eduid_userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid_userdb.phone import PhoneNumber
from eduid_userdb.profile import Profile
from eduid_userdb.tou import ToUEvent
from eduid_userdb.user import User
from eduid_userdb.userdb import UserDB
