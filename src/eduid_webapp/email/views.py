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
from flask import render_template

from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.mail import MailAddress
from eduid_userdb.proofing import EmailProofingElement, SentEmailElement, EmailProofingState
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_common.api.utils import get_unique_hash
from eduid_webapp.email.schemas import EmailSchema, EmailResponseSchema
from eduid_webapp.email.schemas import VerificationCodeSchema

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
    verification_data = {
        'eduPersonPrincipalName': user.eppn,
        'verification': verification.to_dict()
        }
    verification_state = EmailProofingState(verification_data)
    # XXX This should be an atomic transaction together with saving
    # the user and sending the letter.
    current_app.verifications_db.save(verification_state)

    link = url_for('verify', user=user, code=code)
    site_name = current_app.config.get("site.name", "eduID")
    site_url = current_app.config.get("site.url", "http://eduid.se")

    context = {
        "email": email,
        "verification_link": link,
        "site_url": site_url,
        "site_name": site_name,
        "code": code,
    }

    text = render_template(
            "templates/verification_email.txt.jinja2",
            **context
    )
    html = render_template(
            "templates/verification_email.html.jinja2",
            **context
    )

    # DEBUG
    if current_app.config.get('developer_mode', False):
        current_app.logger.debug(message.body)
    else:
        current_app.mail_relay.sendmail(sender, [email], text, html)
    current_app.logger.debug("Sent verification mail to user {!r}"
                             " with address {!s}.".format(request.context.user,
                                                          email))

    return EmailSchema().dump(new_mail).data


@mail_views.route('/primary', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_primary(user, email, confirmed, primary):

    try:
        mail = user.mail_addresses.find(email)
    except IndexError:
        return {
            '_status': 'error',
            'error': {'form': 'user-out-of-sync'}
        }

    if not mail.is_verified:
        message = ('You need to confirm your email address '
                    'before it can become primary')
        return {
            'result': 'bad',
            'message': message
        }

    self.user.mail_addresses.primary = mail.email
    try:
        save_dashboard_user(user)
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'user-out-of-sync'}
        }
    message = ('Your primary email address was '
                'successfully changed')
    return {'result': 'success',
            'message': message}


@mail_views.route('/verify', methods=['GET'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def verify(user, code, email):
    """
    """
    db = current_app.verifications_db
    state = db.get_state_by_eppn_and_code(user.eppn, code)
    verification = state.verification
    timeout = current_app.config.get('EMAIL_VERIFICATION_TIMEOUT', 24)
    if state.is_expired(timeout):
        msg = "Verification code is expired: {!r}".format(verification)
        current_app.logger.debug(msg)
        return {'_status': 'error', 'error': msg}

    if email == verification.email:
        verification.is_verified = True
        verification.verified_ts = datetime.datetime.now()
        verification.verified_by = user.eppn
        state.verification = verification
        current_app.verifications_db.save(state)

        other = current_app.dashboard_userdbb.get_user_by_mail(email)
        if other and other.mail_addresses.primary and \
                other.mail_addresses.primary.email == email:
            # Promote some other verified e-mail address to primary
            for address in other.mail_addresses.to_list():
                if address.is_verified and address.email != email:
                    other.mail_addresses.primary = address.email
                    break
            other.mail_addresses.remove(email)
            save_dashboard_user(other)

        new_email = MailAddress(email = email, application = 'dashboard',
                                verified = True, primary = False)
        if user.mail_addresses.primary is None:
            new_email.is_primary = True
        try:
            user.mail_addresses.add(new_email)
        except DuplicateElementViolation:
            user.mail_addresses.find(email).is_verified = True

        try:
            save_dashboard_user(user)
        except UserOutOfSync:
            return {
                '_status': 'error',
                'error': {'form': 'user-out-of-sync'}
            }
        return new_email.to_dict()


@mail_views.route('/remove', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_remove(user, email, confirmed, primary):
        emails = user.mail_addresses.to_list()
        if len(emails) == 1:
            message = ('Error: You only have one email address and it  '
                        'can not be removed')
            return {
                'result': 'error',
                'message': message,
            }

        try:
            user.mail_addresses.remove(email)
        except PrimaryElementViolation:
            new_index = 1 if emails[0].email == email else 0
            self.user.mail_addresses.primary = emails[new_index].email
            self.user.mail_addresses.remove(remove_email)

        try:
            save_dashboard_user(user)
        except UserOutOfSync:
            return {
                '_status': 'error',
                'error': {'form': 'user-out-of-sync'}
            }

        message = ('Email address was successfully removed')
        return {
            'result': 'success',
            'message': message,
        }
