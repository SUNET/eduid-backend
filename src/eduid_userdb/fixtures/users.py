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
    johnsmith_example_com,
    johnsmith2_example_com,
    johnsmith3_example_com,
    johnsmith_example_com_old,
    johnsmith2_example_com_old,
    johnsmith3_example_com_old_unverified,
)
from eduid_userdb.fixtures.locked_identities import dashboard_locked_nin
from eduid_userdb.fixtures.nins import dashboard_primary_nin, dashboard_verified_nin
from eduid_userdb.fixtures.passwords import signup_password, signup_password_2, old_password
from eduid_userdb.fixtures.pending_emails import johnsmith2_example_com_pending
from eduid_userdb.fixtures.phones import (
    dashboard_primary_phone,
    dashboard_unverified_phone,
    old_primary_phone,
    old_unverified_phone,
)
from eduid_userdb.fixtures.tous import signup_2016_v1
from eduid_userdb.locked_identity import LockedIdentityList
from eduid_userdb.mail import MailAddressList
from eduid_userdb.nin import NinList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.signup import SignupUser
from eduid_userdb.tou import ToUList
from eduid_userdb.user import User

new_user_example = User.construct_user(
    eppn='hubba-bubba',
    _id=ObjectId('012345678901234567890123'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=False,
    mail_addresses=MailAddressList([johnsmith_example_com, johnsmith2_example_com,]),
    nins=NinList([dashboard_primary_nin, dashboard_verified_nin,]),
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone,]),
    passwords=CredentialList([signup_password,]),
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student',],
    locked_identity=LockedIdentityList([dashboard_locked_nin,]),
)


new_signup_user_example = SignupUser.construct_user(
    eppn='hubba-bubba',
    _id=ObjectId('012345678901234567890123'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"),
    terminated=False,
    mail_addresses=MailAddressList([johnsmith_example_com, johnsmith2_example_com,]),
    nins=NinList([dashboard_primary_nin, dashboard_verified_nin,]),
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone,]),
    passwords=CredentialList([signup_password,]),
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student',],
    locked_identity=LockedIdentityList([dashboard_locked_nin,]),
    social_network='facebook',
    social_network_id='hubba-1234',
    pending_mail_address=johnsmith2_example_com_pending
)


empty_nin_lists = NinList([])


completed_signup_mail_addresses = MailAddressList([johnsmith3_example_com])


tous = ToUList([signup_2016_v1])


completed_signup_passwords = CredentialList([signup_password_2])


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
    mail_addresses=completed_signup_mail_addresses,
    nins=empty_nin_lists,
    phone_numbers=phone_numbers,
    passwords=completed_signup_passwords,
    entitlements=[],
    locked_identity=empty_locked_identity
)


old_mail_addresses = MailAddressList([
    johnsmith_example_com_old,
    johnsmith2_example_com_old,
    johnsmith3_example_com_old_unverified,
])


old_phone_numbers = PhoneNumberList([old_primary_phone, old_unverified_phone])


old_postal_addresses = [
    {
        'type': 'home',
        'country': 'SE',
        'address': "Long street, 48",
        'postalCode': "123456",
        'locality': "Stockholm",
        'verified': True,
    },
    {
        'type': 'work',
        'country': 'ES',
        'address': "Calle Ancha, 49",
        'postalCode': "123456",
        'locality': "Punta Umbria",
        'verified': False,
    },
]


old_passwords = CredentialList([old_password])


old_user_example = User.construct_user(
    eppn='hubba-bubba',
    _id=ObjectId('012345678901234567890123'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    language='en',
    modified_ts=datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"),
    mail='johnsmith@example.com',
    mail_addresses=old_mail_addresses,
    norEduPersonNIN=['197801011234'],
    postalAddress=old_postal_addresses,
    mobile=old_phone_numbers,
    passwords=old_passwords,
    eduPersonEntitlement=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student'],
    terminated=None
)
