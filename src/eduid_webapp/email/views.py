# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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
#     3. Neither the name of the NORDUnet nor the names of its
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

from __future__ import absolute_import

from flask import Blueprint

from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.mail import MailAddress
from eduid_userdb.proofing import EmailProofingElement, SentEmailElement
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_common.api.utils import get_unique_hash
from eduid_webapp.email.schemas import EmailSchema, EmailResponseSchema

email_views = Blueprint('email', __name__, url_prefix='')


@email_views.route('/all', methods=['GET'])
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def get_all_emails(user):
    return EmailSchema(many=True).dump(user.mail_addresses).data


@email_views.route('/new', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_email(user, email, confirmed, primary):
    new_mail = MailAddress(email=email, application='dashboard',
                           verified=False, primary=False)
    user.mail_addresses.add(new_mail)
    try:
        save_dashboard_user(user)
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'user-out-of-sync'}
        }

    code = get_unique_hash()
    
    verification = EmailProofingElement(email=email,
                                        verification_code=code,
                                        application='dashboard')

    return EmailSchema().dump(new_mail).data


@mail_views.route('/primary', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_primary(user, email, confirmed, primary):
    pass
