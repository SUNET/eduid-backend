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
    johnsmith2_example_com_old,
    johnsmith3_example_com_unverified,
    johnsmith_example_com_old,
)
from eduid_userdb.fixtures.passwords import old_password
from eduid_userdb.fixtures.phones import old_primary_phone, old_unverified_phone
from eduid_userdb.fixtures.postal_addresses import old_postal_addresses
from eduid_userdb.mail import MailAddressList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.user import User

mail_addresses = MailAddressList(
    [johnsmith_example_com_old, johnsmith2_example_com_old, johnsmith3_example_com_unverified,]
)


phone_numbers = PhoneNumberList([old_primary_phone, old_unverified_phone,])


passwords = CredentialList([old_password])


entitlements = [
    'urn:mace:eduid.se:role:admin',
    'urn:mace:eduid.se:role:student',
]


old_user_example = User.construct_user(
    eppn='hubba-bubba',
    _id=ObjectId('012345678901234567890123'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    language='en',
    modified_ts=datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"),
    mail='johnsmith@example.com',
    mail_addresses=mail_addresses,
    norEduPersonNIN=['197801011234'],
    postalAddress=old_postal_addresses,
    mobile=phone_numbers,
    passwords=passwords,
    eduPersonEntitlement=entitlements,
    terminated=None,
)
