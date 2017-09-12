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

import datetime

from flask import Blueprint, session, abort
from flask import render_template, current_app

from eduid_userdb.element import PrimaryElementViolation, DuplicateElementViolation
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.mail import MailAddress
from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_webapp.email.schemas import EmailListPayload, EmailSchema, SimpleEmailSchema, EmailResponseSchema
from eduid_webapp.email.schemas import VerificationCodeSchema
from eduid_webapp.email.verifications import send_verification_code
from eduid_webapp.email.helpers import save_user, require_user

email_views = Blueprint('email', __name__, url_prefix='', template_folder='templates')


@email_views.route('/all', methods=['GET'])
@MarshalWith(EmailResponseSchema)
@require_user
def get_all_emails(user):
    emails = {
        'emails': user.mail_addresses.to_list_of_dicts(),
        'message': 'emails.get-success'
    }

    return EmailListPayload().dump(emails).data


@email_views.route('/new', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def post_email(user, email, verified, primary):

    current_app.logger.debug('Trying to save unconfirmed email {!r} '
                             'for user {!r}'.format(email, user))

    new_mail = MailAddress(email=email, application='dashboard',
                           verified=False, primary=False)

    try:
        user.mail_addresses.add(new_mail)
    except DuplicateElementViolation:
        return {
            '_status': 'error',
            'message':  'emails.duplicated'
        }

    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save email {!r} for user {!r}, '
                                 'data out of sync'.format(email, user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    current_app.logger.info('Saved unconfirmed email {!r} '
                            'for user {!r}'.format(email, user))
    current_app.stats.count(name='email_save_unconfirmed_email', value=1)

    send_verification_code(email, user)
    current_app.stats.count(name='email_send_verification_code', value=1)

    emails = {
            'emails': user.mail_addresses.to_list_of_dicts(),
            'message': 'emails.save-success'
            }
    return EmailListPayload().dump(emails).data


@email_views.route('/primary', methods=['POST'])
@UnmarshalWith(SimpleEmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def post_primary(user, email):
    current_app.logger.debug('Trying to save email address {!r} as primary '
                             'for user {!r}'.format(email, user))

    try:
        mail = user.mail_addresses.find(email)
    except IndexError:
        current_app.logger.debug('Couldnt save email {!r} as primary for user'
                                 ' {!r}, data out of sync'.format(email, user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }

    if not mail.is_verified:
        current_app.logger.debug('Couldnt save email {!r} as primary for user'
                                 ' {!r}, email unconfirmed'.format(email, user))
        return {
            '_status': 'error',
            'message': 'emails.unconfirmed_address_not_primary'
        }

    user.mail_addresses.primary = mail.email
    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt save email {!r} as primary for user'
                                 ' {!r}, data out of sync'.format(email, user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    current_app.logger.info('Email address {!r} made primary '
                            'for user {!r}'.format(email, user))
    current_app.stats.count(name='email_set_primary', value=1)

    emails = {
            'emails': user.mail_addresses.to_list_of_dicts(),
            'message': 'emails.primary-success'
            }
    return EmailListPayload().dump(emails).data


@email_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def verify(user, code, email):
    """
    """
    current_app.logger.debug('Trying to save email address {!r} as verified '
                             'for user {!r}'.format(email, user))

    db = current_app.verifications_db
    state = db.get_state_by_eppn_and_email(user.eppn, email)

    timeout = current_app.config.get('EMAIL_VERIFICATION_TIMEOUT', 24)
    if state.is_expired(timeout):
        msg = "Verification code is expired: {!r}. Sending new code".format(
                state.verification)
        current_app.logger.debug(msg)

        send_verification_code(email, user)
        return {
            '_status': 'error',
            'message': 'emails.code_expired_send_new'
        }

    if code != state.verification.verification_code:
        msg = "Invalid verification code: {!r}".format(state.verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'message': 'emails.code_invalid'
        }

    current_app.verifications_db.remove_state(state)
    msg = 'Removed verification code: {!r} '.format(state.verification)
    current_app.logger.debug(msg)

    new_email = MailAddress(email = email, application = 'dashboard',
                            verified = True, primary = False)

    has_primary = user.mail_addresses.primary
    if has_primary is None:
        new_email.is_primary = True
    try:
        user.mail_addresses.add(new_email)
    except DuplicateElementViolation:
        user.mail_addresses.find(email).is_verified = True
        if has_primary is None:
            user.mail_addresses.find(email).is_primary = True

    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt confirm email {!r} for user'
                                 ' {!r}, data out of sync'.format(email, user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    current_app.logger.info('Email address {!r} confirmed '
                            'for user {!r}'.format(email, user))
    current_app.stats.count(name='email_verify_success', value=1)

    emails = {
            'emails': user.mail_addresses.to_list_of_dicts(),
            'message': 'emails.verification-success'
            }
    return EmailListPayload().dump(emails).data


@email_views.route('/remove', methods=['POST'])
@UnmarshalWith(SimpleEmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def post_remove(user, email):
    current_app.logger.debug('Trying to remove email address {!r} '
                             'from user {!r}'.format(email, user))

    emails = user.mail_addresses.to_list()
    if len(emails) == 1:
        msg = "Cannot remove unique address: {!r}".format(email)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'message': 'emails.cannot_remove_unique'
        }

    try:
        user.mail_addresses.remove(email)
    except PrimaryElementViolation:
        new_index = 1 if emails[0].email == email else 0
        user.mail_addresses.primary = emails[new_index].email
        user.mail_addresses.remove(email)

    try:
        save_user(user)
    except UserOutOfSync:
        current_app.logger.debug('Couldnt remove email {!r} for user'
                                 ' {!r}, data out of sync'.format(email, user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }

    except PrimaryElementViolation:
        return {
            '_status': 'error',
            'message': 'emails.cannot_remove_primary'
        }

    current_app.logger.info('Email address {!r} removed '
                            'for user {!r}'.format(email, user))
    current_app.stats.count(name='email_remove_success', value=1)

    emails = {
            'emails': user.mail_addresses.to_list_of_dicts(),
            'message': 'emails.removal-success'
            }
    return EmailListPayload().dump(emails).data


@email_views.route('/resend-code', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_user
def resend_code(user, email):
    current_app.logger.debug('Trying to send new verification code for email '
                             'address {!r} for user {!r}'.format(email, user))

    if not user.mail_addresses.find(email):
        current_app.logger.debug('Unknown email {!r} in resend_code_action,'
                                 ' user {!s}'.format(email, user))
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    
    send_verification_code(email, user)
    current_app.logger.debug('New verification code sended to '
                             'address {!r} for user {!r}'.format(email, user))
    current_app.stats.count(name='email_resend_code', value=1)

    emails = {
            'emails': user.mail_addresses.to_list_of_dicts(),
            'message': 'emails.code-sent'
            }
    return EmailListPayload().dump(emails).data
