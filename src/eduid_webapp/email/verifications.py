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

from flask import current_app, url_for, render_template

from eduid_userdb.mail import MailAddress
from eduid_userdb.element import DuplicateElementViolation
from eduid_common.api.utils import get_unique_hash, save_and_sync_user
from eduid_userdb.proofing import EmailProofingElement, EmailProofingState


def new_verification_code(email, user):
    old_verification = current_app.proofing_statedb.get_state_by_eppn_and_email(
            user.eppn, email, raise_on_missing=False)
    if old_verification is not None:
        current_app.logger.debug('removing old verification code:'
                                 ' {!r}.'.format(old_verification.to_dict()))
        current_app.proofing_statedb.remove_state(old_verification)
    code = get_unique_hash()
    verification = EmailProofingElement(email=email,
                                        verification_code=code,
                                        application='email')
    verification_data = {
        'eduPersonPrincipalName': user.eppn,
        'verification': verification.to_dict()
        }
    verification_state = EmailProofingState(verification_data)
    # XXX This should be an atomic transaction together with saving
    # the user and sending the letter.
    current_app.proofing_statedb.save(verification_state)

    current_app.logger.info('Created new email verification code '
                            'for user {!r} and email {!r}.'.format(user, email))
    current_app.logger.debug('Verification Code:'
                             ' {!r}.'.format(verification_state.to_dict()))

    return code


def send_verification_code(email, user):
    code = new_verification_code(email, user)
    link = url_for('email.verify_link', code=code, email=email, _external=True)
    site_name = current_app.config.get("EDUID_SITE_NAME")
    site_url = current_app.config.get("EDUID_SITE_URL")

    context = {
        "email": email,
        "verification_link": link,
        "site_url": site_url,
        "site_name": site_name,
        "code": code,
    }

    text = render_template(
            "verification_email.txt.jinja2",
            **context
    )
    html = render_template(
            "verification_email.html.jinja2",
            **context
    )

    sender = current_app.config.get('MAIL_DEFAULT_FROM')
    # DEBUG
    if current_app.config.get('DEBUG', False):
        current_app.logger.debug(text)
    else:
        current_app.mail_relay.sendmail(sender, [email], text, html)
    current_app.logger.info("Sent email address verification mail to user {!r}"
                            " about address {!s}.".format(user, email))


def verify_mail_address(state, proofing_user):
    """
    :param proofing_user: ProofingUser
    :param state: E-mail proofing state

    :type proofing_user: eduid_userdb.proofing.ProofingUser
    :type state: EmailProofingState

    :return: None

    """
    new_email = MailAddress(email=state.verification.email, application='email',
                            verified=True, primary=False)

    has_primary = proofing_user.mail_addresses.primary
    if has_primary is None:
        new_email.is_primary = True
    try:
        proofing_user.mail_addresses.add(new_email)
    except DuplicateElementViolation:
        proofing_user.mail_addresses.find(state.verification.email).is_verified = True
        if has_primary is None:
            proofing_user.mail_addresses.find(state.verification.email).is_primary = True

    save_and_sync_user(proofing_user)
    current_app.logger.info('Email address {!r} confirmed '
                            'for user {!r}'.format(state.verification.email, proofing_user))
    current_app.stats.count(name='email_verify_success', value=1)
    current_app.proofing_statedb.remove_state(state)
    current_app.logger.debug('Removed proofing state: {} '.format(state))
