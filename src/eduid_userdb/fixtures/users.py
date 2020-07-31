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
    johnsmith2_example_com,
    johnsmith2_example_com_old,
    johnsmith2_example_org,
    johnsmith3_example_com,
    johnsmith3_example_com_unverified,
    johnsmith_example_com,
    johnsmith_example_com_old,
    johnsmith_example_org,
)
from eduid_userdb.fixtures.locked_identities import dashboard_locked_nin
from eduid_userdb.fixtures.nins import dashboard_primary_nin, dashboard_verified_nin
from eduid_userdb.fixtures.passwords import old_password, signup_password, signup_password_2
from eduid_userdb.fixtures.pending_emails import johnsmith2_example_com_pending
from eduid_userdb.fixtures.phones import (
    dashboard_primary_phone,
    dashboard_unverified_phone,
    dashboard_verified_phone,
    old_primary_phone,
    old_unverified_phone,
)
from eduid_userdb.fixtures.postal_addresses import old_postal_addresses
from eduid_userdb.fixtures.tous import signup_2016_v1
from eduid_userdb.locked_identity import LockedIdentityList
from eduid_userdb.mail import MailAddressList
from eduid_userdb.nin import NinList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.signup.user import SignupUser
from eduid_userdb.tou import ToUList
from eduid_userdb.user import User

mocked_user_standard = User(
    eppn='hubba-bubba',
    user_id=ObjectId('012345678901234567890123'),
    given_name='John',
    surname='Smith',
    display_name='John Smith',
    nins=NinList([dashboard_primary_nin]),
    language='en',
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student'],
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_verified_phone, dashboard_unverified_phone,]),
    mail_addresses=MailAddressList(
        [johnsmith_example_com, johnsmith2_example_com_old, johnsmith3_example_com_unverified,]
    ),
    credentials=CredentialList([signup_password]),
)


mocked_user_standard_2 = User(
    eppn='babba-labba',
    user_id=ObjectId('901234567890123456789012'),
    given_name='John',
    surname='Smith',
    display_name='John Smith',
    nins=NinList([]),
    language='en',
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student'],
    phone_numbers=PhoneNumberList([]),
    mail_addresses=MailAddressList([johnsmith_example_org, johnsmith2_example_org,]),
    credentials=CredentialList([signup_password]),
)

new_completed_signup_user_example = User(
    eppn='hubba-fooo',
    user_id=ObjectId('000000000000000000000002'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.fromisoformat("2017-01-04T16:47:30"),
    tou=ToUList([signup_2016_v1]),
    terminated=None,
    mail_addresses=MailAddressList([johnsmith3_example_com]),
    nins=NinList([]),
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList([signup_password_2]),
    entitlements=[],
    locked_identity=LockedIdentityList([]),
)


new_signup_user_example = SignupUser(
    eppn='hubba-bubba',
    user_id=ObjectId('012345678901234567890123'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=None,
    mail_addresses=MailAddressList([johnsmith_example_com, johnsmith2_example_com]),
    nins=NinList([dashboard_primary_nin, dashboard_verified_nin]),
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList([signup_password]),
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student',],
    locked_identity=LockedIdentityList([dashboard_locked_nin]),
    social_network='facebook',
    social_network_id='hubba-1234',
    pending_mail_address=johnsmith2_example_com_pending,
)


new_unverified_user_example = User(
    eppn='hubba-baar',
    user_id=ObjectId('000000000000000000000003'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=None,
    mail_addresses=MailAddressList([johnsmith_example_com, johnsmith2_example_com]),
    nins=NinList([]),
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList([signup_password]),
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student',],
    locked_identity=LockedIdentityList([]),
)


new_user_example = User(
    eppn='hubba-bubba',
    user_id=ObjectId('012345678901234567890123'),
    given_name='John',
    display_name='John Smith',
    surname='Smith',
    subject='physical person',
    language='en',
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=None,
    mail_addresses=MailAddressList([johnsmith_example_com, johnsmith2_example_com]),
    nins=NinList([dashboard_primary_nin, dashboard_verified_nin]),
    phone_numbers=PhoneNumberList([dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList([signup_password]),
    entitlements=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student',],
    locked_identity=LockedIdentityList([dashboard_locked_nin]),
)


old_user_example = User.from_dict(
    dict(
        eduPersonPrincipalName='hubba-bubba',
        _id=ObjectId('012345678901234567890123'),
        givenName='John',
        displayName='John Smith',
        surname='Smith',
        preferredLanguage='en',
        modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
        mailAliases=MailAddressList(
            [johnsmith_example_com_old, johnsmith2_example_com_old, johnsmith3_example_com_unverified, ]
        ).to_list_of_dicts(),
        norEduPersonNIN=['197801011234'],
        postalAddress=old_postal_addresses,
        phone=PhoneNumberList([old_primary_phone, old_unverified_phone, ]).to_list_of_dicts(),
        passwords=CredentialList([old_password]).to_list_of_dicts(),
        eduPersonEntitlement=['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student', ],
        terminated=None,
    )
)
