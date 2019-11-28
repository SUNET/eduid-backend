# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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

from typing import Union

from flask import url_for
from flask_babel import gettext as _

from eduid_userdb.exceptions import UserHasNotCompletedSignup
from eduid_userdb.security import PasswordResetEmailState
from eduid_common.api.utils import get_unique_hash
from eduid_webapp.security.helpers import send_mail
from eduid_webapp.reset_password.app import current_reset_password_app as current_app


def success_message(message: Union[str, bytes]) -> dict:
    return {
        '_status': 'ok',
        'message': str(message)
    }


def error_message(message: Union[str, bytes]) -> dict:
    return {
        '_status': 'error',
        'message': str(message)
    }


def send_password_reset_mail(email_address):
    """
    :param email_address: User input for password reset
    :type email_address: six.string_types
    :return:
    :rtype:
    """
    try:
        user = current_app.central_userdb.get_user_by_mail(email_address, raise_on_missing=False)
    except UserHasNotCompletedSignup:
        # Old bug where incomplete signup users where written to the central db
        user = None
    if not user:
        current_app.logger.info("Found no user with the following address: {}.".format(email_address))
        return None
    state = PasswordResetEmailState(eppn=user.eppn, email_address=email_address, email_code=get_unique_hash())
    current_app.password_reset_state_db.save(state)
    text_template = 'reset_password_email.txt.jinja2'
    html_template = 'reset_password_email.html.jinja2'
    to_addresses = [address.email for address in user.mail_addresses.verified.to_list()]

    password_reset_timeout = current_app.config.email_code_timeout // 60 // 60  # seconds to hours
    context = {
        'reset_password_link': url_for('reset_password.set_new_pw', email_code=state.email_code.code,
                                       _external=True),
        'password_reset_timeout': password_reset_timeout
    }
    subject = _('Reset password')
    send_mail(subject, to_addresses, text_template, html_template, context, state.reference)
    current_app.logger.info('Sent password reset email to user {}'.format(state.eppn))
    current_app.logger.debug('Mail address: {}'.format(to_addresses))
