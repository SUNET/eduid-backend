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
from datetime import datetime
from urllib import urlencode
import urlparse

from flask import Blueprint, session, abort, url_for
from flask import render_template, current_app

from eduid_userdb.exceptions import UserOutOfSync
from eduid_common.api.utils import urlappend
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_common.authn.utils import generate_password
from eduid_common.authn.vccs import add_credentials, revoke_all_credentials
from eduid_webapp.security.schemas import SecurityResponseSchema, CredentialList, CsrfSchema
from eduid_webapp.security.schemas import SuggestedPassword, SuggestedPasswordResponseSchema
from eduid_webapp.security.schemas import ChangePasswordSchema, RedirectResponseSchema
from eduid_webapp.security.schemas import RedirectSchema, AccountTerminatedSchema, ChpassResponseSchema

security_views = Blueprint('security', __name__, url_prefix='', template_folder='templates')


def error(err):
    return {
        '_status': 'error',
        'error': {'form': err}
        }


@security_views.route('/credentials', methods=['GET'])
@MarshalWith(SecurityResponseSchema)
@require_dashboard_user
def get_credentials(user):
    """
    View to get credentials for the logged user.
    """
    csrf_token = session.get_csrf_token()
    current_app.logger.debug('Triying to get the credentials '
                             'for user {!r}'.format(user))
    credentials =  {
        'csrf_token': csrf_token,
        'credentials': current_app.authninfo_db.get_authn_info(user)
        }

    return CredentialList().dump(credentials).data


@security_views.route('/suggested-password', methods=['GET'])
@MarshalWith(SuggestedPasswordResponseSchema)
@require_dashboard_user
def get_suggested(user):
    """
    View to get a suggested  password for the logged user.
    """
    current_app.logger.debug('Triying to get the credentials '
                             'for user {!r}'.format(user))
    suggested = {
            'suggested_password': generate_suggested_password()
            }

    return SuggestedPassword().dump(suggested).data


def generate_suggested_password():
    """
    The suggested password is saved in session to avoid form hijacking
    """
    password_length = current_app.config.get('PASSWORD_LENGTH', 12)

    password = generate_password(length=password_length)
    password = ' '.join([password[i*4: i*4+4] for i in range(0, len(password)/4)])

    session['last_generated_password'] = password
    return password


@security_views.route('/change-password', methods=['POST'])
@MarshalWith(ChpassResponseSchema)
@UnmarshalWith(ChangePasswordSchema)
@require_dashboard_user
def change_password(user, csrf_token, old_password, new_password):
    """
    View to chhange the password
    """
    if session.get_csrf_token() != csrf_token:
        abort(400)

    authn_ts = session.get('reauthn-for-chpass', None)
    if authn_ts is None:
        return error('chpass.no_reauthn')

    now = datetime.utcnow()
    delta = now - datetime.fromtimestamp(authn_ts)
    timeout = current_app.config.get('CHPASS_TIMEOUT', 600)
    if int(delta.total_seconds()) > timeout:
        return error('chpass.stale_reauthn')

    del session['reauthn-for-chpass']

    vccs_url = current_app.config.get('VCCS_URL')
    added = add_credentials(vccs_url, old_password, new_password,
                    user, source='security')

    if added:
        user.terminated = False
        try:
            save_dashboard_user(user)
        except UserOutOfSync:
            return error('out_of_sync')
    else:
        return error('chpass.unknown_error')

    current_app.stats.count(name='security_password_changed', value=1)
    current_app.logger.info('Changed password for user {!r}'.format(user.eppn))

    next_url = current_app.config.get('DASHBOARD_URL', '/profile')
    credentials =  {
        'csrf_token': csrf_token,
        'next_url': next_url,
        'credentials': current_app.authninfo_db.get_authn_info(user)
        }

    return CredentialList().dump(credentials).data


@security_views.route('/terminate-account', methods=['POST'])
@MarshalWith(RedirectResponseSchema)
@UnmarshalWith(CsrfSchema)
@require_dashboard_user
def delete_account(user, csrf_token):
    """
    Terminate account view.
    It receives a POST request, checks the csrf token,
    schedules the account termination action,
    and redirects to the IdP.
    """
    # check csrf
    if session.get_csrf_token() != csrf_token:
        abort(400)

    current_app.logger.debug('Initiating account termination for user {!r}'.format(user))

    ts_url = current_app.config.get('TOKEN_SERVICE_URL')
    terminate_url = urlappend(ts_url, 'terminate')
    next_url = url_for('security.account_terminated')

    params = {'next': next_url}

    url_parts = list(urlparse.urlparse(terminate_url))
    query = urlparse.parse_qs(url_parts[4])
    query.update(params)

    url_parts[4] = urlencode(query)
    location = urlparse.urlunparse(url_parts)
    return RedirectSchema().dump({'location': location}).data


@security_views.route('/account-terminated', methods=['GET'])
@MarshalWith(AccountTerminatedSchema)
@require_dashboard_user
def account_terminated(user):
    """
    The account termination action,
    removes all credentials for the terminated account
    from the VCCS service,
    flags the account as terminated,
    sends an email to the address in the terminated account,
    and logs out the session.

    :type user: eduid_userdb.dashboard.DashboardLegacyUser
    """
    authn_ts = session.get('reauthn-for-termination', None)
    if authn_ts is None:
        abort(400)

    now = datetime.utcnow()
    delta = now - datetime.fromtimestamp(authn_ts)

    if int(delta.total_seconds()) > 600:
        return error('security.stale_authn_info')

    del session['reauthn-for-termination']

    # revoke all user credentials
    revoke_all_credentials(current_app.config.get('VCCS_URL'), user)
    for p in user.passwords.to_list():
        user.passwords.remove(p.id)

    # flag account as terminated
    user.terminated = True
    try:
        save_dashboard_user(user)
    except UserOutOfSync:
        return error('out_of_sync')

    current_app.stats.count(name='security_account_terminated', value=1)
    current_app.logger.info('Terminated account for user {!r}'.format(user))

    # email the user
    send_termination_mail(user)

    return {}


def send_termination_mail(user):
    site_name = current_app.config.get("site.name", "eduID")
    site_url = current_app.config.get("site.url", "http://eduid.se")

    context = {
        "user": user,
        "site_url": site_url,
        "site_name": site_name,
    }

    text = render_template(
            "termination_email.txt.jinja2",
            **context
    )
    html = render_template(
            "termination_email.html.jinja2",
            **context
    )

    sender = current_app.config.get('MAIL_DEFAULT_FROM')
    # DEBUG
    if current_app.config.get('DEBUG', False):
        current_app.logger.debug(text)
    else:
        current_app.mail_relay.sendmail(sender, [email], text, html)
    current_app.logger.info("Sent termination email to user {!r}".format(user))
