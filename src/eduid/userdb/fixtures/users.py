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

from eduid.userdb.credentials import CredentialList
from eduid.userdb.fixtures.email_addresses import (
    johnsmith2_example_com,
    johnsmith2_example_com_old,
    johnsmith2_example_org,
    johnsmith3_example_com,
    johnsmith3_example_com_unverified,
    johnsmith_example_com,
    johnsmith_example_com_old,
    johnsmith_example_org,
)
from eduid.userdb.fixtures.identity import verified_eidas_identity, verified_nin_identity
from eduid.userdb.fixtures.ladok import dashboard_ladok
from eduid.userdb.fixtures.locked_identities import dashboard_locked_nin
from eduid.userdb.fixtures.nins import dashboard_primary_nin, dashboard_verified_nin
from eduid.userdb.fixtures.orcid import dashboard_orcid
from eduid.userdb.fixtures.passwords import old_password, signup_password, signup_password_2
from eduid.userdb.fixtures.pending_emails import johnsmith2_example_com_pending
from eduid.userdb.fixtures.phones import (
    dashboard_primary_phone,
    dashboard_unverified_phone,
    dashboard_verified_phone,
    old_primary_phone,
    old_unverified_phone,
)
from eduid.userdb.fixtures.tous import signup_2016_v1
from eduid.userdb.identity import IdentityList
from eduid.userdb.locked_identity import LockedIdentityList
from eduid.userdb.mail import MailAddressList
from eduid.userdb.nin import NinList
from eduid.userdb.phone import PhoneNumberList
from eduid.userdb.signup.user import SignupUser
from eduid.userdb.tou import ToUList
from eduid.userdb.user import SubjectType, User

mocked_user_standard = User(
    eppn="hubba-bubba",
    user_id=ObjectId("012345678901234567890123"),
    given_name="John",
    surname="Smith",
    display_name="John Smith",
    identities=IdentityList(elements=[verified_nin_identity]),
    language="en",
    entitlements=["urn:mace:eduid.se:role:admin", "urn:mace:eduid.se:role:student"],
    phone_numbers=PhoneNumberList(
        elements=[dashboard_primary_phone, dashboard_verified_phone, dashboard_unverified_phone]
    ),
    mail_addresses=MailAddressList(
        elements=[johnsmith_example_com, johnsmith2_example_com_old, johnsmith3_example_com_unverified]
    ),
    credentials=CredentialList(elements=[signup_password]),
    orcid=dashboard_orcid,
    ladok=dashboard_ladok,
)


mocked_user_standard_2 = User(
    eppn="babba-labba",
    user_id=ObjectId("901234567890123456789012"),
    given_name="John",
    surname="Smith",
    display_name="John Smith",
    identities=IdentityList(),
    language="en",
    entitlements=["urn:mace:eduid.se:role:admin", "urn:mace:eduid.se:role:student"],
    phone_numbers=PhoneNumberList(),
    mail_addresses=MailAddressList(elements=[johnsmith_example_org, johnsmith2_example_org]),
    credentials=CredentialList(elements=[signup_password]),
)

new_completed_signup_user_example = User(
    eppn="hubba-fooo",
    user_id=ObjectId("000000000000000000000002"),
    given_name="John",
    display_name="John Smith",
    surname="Smith",
    subject=SubjectType.PERSON,
    language="en",
    modified_ts=datetime.fromisoformat("2017-01-04T16:47:30"),
    tou=ToUList(elements=[signup_2016_v1]),
    terminated=None,
    mail_addresses=MailAddressList(elements=[johnsmith3_example_com]),
    identities=IdentityList(),
    phone_numbers=PhoneNumberList(elements=[dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList(elements=[signup_password_2]),
    entitlements=[],
    locked_identity=LockedIdentityList(),
)


new_signup_user_example = SignupUser(
    eppn="hubba-bubba",
    user_id=ObjectId("012345678901234567890123"),
    given_name="John",
    display_name="John Smith",
    surname="Smith",
    subject=SubjectType.PERSON,
    language="en",
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=None,
    mail_addresses=MailAddressList(elements=[johnsmith_example_com, johnsmith2_example_com]),
    identities=IdentityList(),
    phone_numbers=PhoneNumberList(elements=[dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList(elements=[signup_password]),
    entitlements=[
        "urn:mace:eduid.se:role:admin",
        "urn:mace:eduid.se:role:student",
    ],
    locked_identity=LockedIdentityList(elements=[dashboard_locked_nin]),
    social_network="facebook",
    social_network_id="hubba-1234",
    pending_mail_address=johnsmith2_example_com_pending,
)


new_unverified_user_example = User(
    eppn="hubba-baar",
    user_id=ObjectId("000000000000000000000003"),
    given_name="John",
    display_name="John Smith",
    surname="Smith",
    subject=SubjectType("physical person"),
    language="en",
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=None,
    mail_addresses=MailAddressList(elements=[johnsmith_example_com, johnsmith2_example_com]),
    identities=IdentityList(),
    phone_numbers=PhoneNumberList(elements=[dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList(elements=[signup_password]),
    entitlements=[
        "urn:mace:eduid.se:role:admin",
        "urn:mace:eduid.se:role:student",
    ],
    locked_identity=LockedIdentityList(),
)


new_user_example = User(
    eppn="hubba-bubba",
    user_id=ObjectId("012345678901234567890123"),
    given_name="John",
    display_name="John Smith",
    surname="Smith",
    subject=SubjectType("physical person"),
    language="en",
    modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    terminated=None,
    mail_addresses=MailAddressList(elements=[johnsmith_example_com, johnsmith2_example_com]),
    identities=IdentityList(elements=[verified_nin_identity, verified_eidas_identity]),
    phone_numbers=PhoneNumberList(elements=[dashboard_primary_phone, dashboard_unverified_phone]),
    credentials=CredentialList(elements=[signup_password]),
    entitlements=[
        "urn:mace:eduid.se:role:admin",
        "urn:mace:eduid.se:role:student",
    ],
    locked_identity=LockedIdentityList(elements=[dashboard_locked_nin]),
    ladok=dashboard_ladok,
)


old_user_example = User.from_dict(
    dict(
        eduPersonPrincipalName="hubba-bubba",
        _id=ObjectId("012345678901234567890123"),
        givenName="John",
        displayName="John Smith",
        surname="Smith",
        preferredLanguage="en",
        modified_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
        mailAliases=MailAddressList(
            elements=[
                johnsmith_example_com_old,
                johnsmith2_example_com_old,
                johnsmith3_example_com_unverified,
            ]
        ).to_list_of_dicts(),
        nins=NinList(elements=[dashboard_primary_nin, dashboard_verified_nin]).to_list_of_dicts(),
        phone=PhoneNumberList(
            elements=[
                old_primary_phone,
                old_unverified_phone,
            ]
        ).to_list_of_dicts(),
        passwords=CredentialList(elements=[old_password]).to_list_of_dicts(),
        eduPersonEntitlement=[
            "urn:mace:eduid.se:role:admin",
            "urn:mace:eduid.se:role:student",
        ],
        terminated=None,
    )
)
