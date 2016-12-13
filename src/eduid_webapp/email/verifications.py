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

from eduid_common.api.utils import get_unique_hash
from eduid_userdb.proofing import EmailProofingElement, EmailProofingState


def new_verification_code(email, user):
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
    return code



    doc_id = request.db.verifications.insert(obj)
    reference = unicode(doc_id)
    session_verifications = request.session.get('verifications', [])
    session_verifications.append(code)
    request.session['verifications'] = session_verifications
    log.info('Created new {!s} verification code for user {!r}.'.format(model_name, user))
    log.debug('Verification object id {!s}. Code: {!s}.'.format(obj_id, code))
    return reference, code


def send_verification_code(email, user):
    code = new_verification_code(email, user)
    link = url_for('email.verify', user=user, code=code)
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
    current_app.logger.debug("Sent verification mail to user {!r}"
                             " with address {!s}.".format(user, email))
