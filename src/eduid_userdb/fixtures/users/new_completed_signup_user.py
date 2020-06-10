# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the SUNET nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
from datetime import datetime

from bson import ObjectId

from eduid_userdb.credentials import CredentialList
from eduid_userdb.fixtures.email_addresses import (
    johnsmith3_example_com,
)
from eduid_userdb.fixtures.passwords import signup_password_2
from eduid_userdb.fixtures.phones import (
    dashboard_primary_phone,
    dashboard_unverified_phone,
)
from eduid_userdb.fixtures.tous import signup_2016_v1
from eduid_userdb.locked_identity import LockedIdentityList
from eduid_userdb.mail import MailAddressList
from eduid_userdb.nin import NinList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.tou import ToUList
from eduid_userdb.user import User


mail_addresses = MailAddressList([johnsmith3_example_com])


empty_nin_list = NinList([])


phone_numbers = PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone])


tous = ToUList([signup_2016_v1])


passwords = CredentialList([signup_password_2])


empty_locked_identity = LockedIdentityList([])


new_completed_signup_user_example = User.construct_user(
    eppn='hubba-fooo',
    _id=ObjectId('000000000000000000000002'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.strptime("2017-01-04T16:47:30", "%Y-%m-%dT%H:%M:%S"),
    tou=tous,
    terminated=False,
    mail_addresses=mail_addresses,
    nins=empty_nin_list,
    phone_numbers=phone_numbers,
    passwords=passwords,
    entitlements=[],
    locked_identity=empty_locked_identity,
)
