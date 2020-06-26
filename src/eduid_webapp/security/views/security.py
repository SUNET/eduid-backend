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

import json
from datetime import datetime

from flask import Blueprint, abort, redirect, request, url_for
from marshmallow import ValidationError
from six.moves.urllib_parse import parse_qs, urlencode, urlparse, urlunparse

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.exceptions import AmTaskFailed, MsgTaskFailed
from eduid_common.api.helpers import add_nin_to_user
from eduid_common.api.messages import CommonMsg, error_response, success_response
from eduid_common.api.utils import save_and_sync_user, urlappend
from eduid_common.authn.vccs import add_credentials, revoke_all_credentials
from eduid_common.session import session
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.proofing import NinProofingElement
from eduid_userdb.proofing.state import NinProofingState
from eduid_userdb.security import SecurityUser

from eduid_webapp.security.app import current_security_app as current_app
from eduid_webapp.security.helpers import (
    SecurityMsg,
    compile_credential_list,
    generate_suggested_password,
    get_zxcvbn_terms,
    remove_nin_from_user,
    send_termination_mail,
)
from eduid_webapp.security.schemas import (
    AccountTerminatedSchema,
    ChangePasswordSchema,
    ChpassResponseSchema,
    CsrfSchema,
    NINRequestSchema,
    NINResponseSchema,
    RedirectResponseSchema,
    SecurityResponseSchema,
    SuggestedPasswordResponseSchema,
)

security_views = Blueprint('security', __name__, url_prefix='', template_folder='templates')


@security_views.route('/credentials', methods=['GET'])
@MarshalWith(SecurityResponseSchema)
@require_user
def get_credentials(user):
    """
    View to get credentials for the logged user.
    """
    current_app.logger.debug('Trying to get the credentials ' 'for user {}'.format(user))

    credentials = {'credentials': compile_credential_list(user)}

    return credentials


@security_views.route('/suggested-password', methods=['GET'])
@MarshalWith(SuggestedPasswordResponseSchema)
@require_user
def get_suggested(user):
    """
    View to get a suggested  password for the logged user.
    """
    current_app.logger.debug('Triying to get the credentials ' 'for user {}'.format(user))
    suggested = {'suggested_password': generate_suggested_password()}

    return suggested


@security_views.route('/change-password', methods=['POST'])
@MarshalWith(ChpassResponseSchema)
@require_user
def change_password(user):
    """
    View to change the password
    """
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    min_entropy = current_app.config.password_entropy
    schema = ChangePasswordSchema(zxcvbn_terms=get_zxcvbn_terms(security_user.eppn), min_entropy=int(min_entropy))

    if not request.data:
        return error_response(message='chpass.no-data')

    try:
        form = schema.load(json.loads(request.data))
        current_app.logger.debug(form)
    except ValidationError as e:
        current_app.logger.error(e)
        return error_response(message='chpass.weak-password')
    else:
        old_password = form.get('old_password')
        new_password = form.get('new_password')

    if session.get_csrf_token() != form['csrf_token']:
        return error_response(message='csrf.try_again')

    authn_ts = session.get('reauthn-for-chpass', None)
    if authn_ts is None:
        return error_response(message='chpass.no_reauthn')

    now = datetime.utcnow()
    delta = now - datetime.fromtimestamp(authn_ts)
    timeout = current_app.config.chpass_timeout
    if int(delta.total_seconds()) > timeout:
        return error_response(message='chpass.stale_reauthn')

    vccs_url = current_app.config.vccs_url
    added = add_credentials(vccs_url, old_password, new_password, security_user, source='security')

    if not added:
        current_app.logger.debug('Problem verifying the old credentials for {}'.format(user))
        return error_response(message='chpass.unable-to-verify-old-password')

    security_user.terminated = False
    try:
        save_and_sync_user(security_user)
    except UserOutOfSync:
        return error_response(message='user-out-of-sync')

    del session['reauthn-for-chpass']

    current_app.stats.count(name='security_password_changed', value=1)
    current_app.logger.info('Changed password for user {}'.format(security_user.eppn))

    next_url = current_app.config.dashboard_url
    credentials = {
        'next_url': next_url,
        'credentials': compile_credential_list(security_user),
        'message': 'chpass.password-changed',
    }

    return credentials


@security_views.route('/terminate-account', methods=['POST'])
@MarshalWith(RedirectResponseSchema)
@UnmarshalWith(CsrfSchema)
@require_user
def delete_account(user):
    """
    Terminate account view.
    It receives a POST request, checks the csrf token,
    schedules the account termination action,
    and redirects to the IdP.
    """
    current_app.logger.debug('Initiating account termination for user {}'.format(user))

    ts_url = current_app.config.token_service_url
    terminate_url = urlappend(ts_url, 'terminate')
    next_url = url_for('security.account_terminated')

    params = {'next': next_url}

    url_parts = list(urlparse(terminate_url))
    query = parse_qs(url_parts[4])
    query.update(params)

    url_parts[4] = urlencode(query)
    location = urlunparse(url_parts)
    return {'location': location}


@security_views.route('/account-terminated', methods=['GET'])
@MarshalWith(AccountTerminatedSchema)
@require_user
def account_terminated(user):
    """
    The account termination action,
    removes all credentials for the terminated account
    from the VCCS service,
    flags the account as terminated,
    sends an email to the address in the terminated account,
    and logs out the session.

    :type user: eduid_userdb.user.User
    """
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    authn_ts = session.get('reauthn-for-termination', None)
    if authn_ts is None:
        abort(400)

    now = datetime.utcnow()
    delta = now - datetime.fromtimestamp(authn_ts)

    if int(delta.total_seconds()) > 600:
        return error_response(message=SecurityMsg.stale_reauthn)

    del session['reauthn-for-termination']

    # revoke all user passwords
    revoke_all_credentials(current_app.config.vccs_url, security_user)
    # Skip removing old passwords from the user at this point as a password reset will do that anyway.
    # This fixes the problem with loading users for a password reset as users without passwords triggers
    # the UserHasNotCompletedSignup check in eduid-userdb.
    # TODO: Needs a decision on how to handle unusable user passwords
    # for p in security_user.credentials.filter(Password).to_list():
    #    security_user.passwords.remove(p.key)

    # flag account as terminated
    security_user.terminated = True
    try:
        save_and_sync_user(security_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.stats.count(name='security_account_terminated', value=1)
    current_app.logger.info('Terminated user account')

    # email the user
    try:
        send_termination_mail(security_user)
    except MsgTaskFailed as e:
        current_app.logger.error(f'Failed to send account termination mail: {e}')
        current_app.logger.error('Account will be terminated successfully anyway.')

    current_app.logger.debug(f'Logging out (terminated) user {user}')
    return redirect(f'{current_app.config.logout_endpoint}?next={current_app.config.termination_redirect_url}')


@security_views.route('/remove-nin', methods=['POST'])
@UnmarshalWith(NINRequestSchema)
@MarshalWith(NINResponseSchema)
@require_user
def remove_nin(user, nin):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    current_app.logger.info('Removing NIN from user')
    current_app.logger.debug('NIN: {}'.format(nin))

    nin_obj = security_user.nins.find(nin)
    if nin_obj and nin_obj.is_verified:
        current_app.logger.info('NIN verified. Will not remove it.')
        return error_response(message=SecurityMsg.rm_verified)

    try:
        remove_nin_from_user(security_user, nin)
        return success_response(
            payload=dict(nins=security_user.nins.to_list_of_dicts()), message=SecurityMsg.rm_success
        )
    except AmTaskFailed as e:
        current_app.logger.error('Removing nin from user failed')
        current_app.logger.debug(f'NIN: {nin}')
        current_app.logger.error('{}'.format(e))
        return error_response(message=CommonMsg.temp_problem)


@security_views.route('/add-nin', methods=['POST'])
@UnmarshalWith(NINRequestSchema)
@MarshalWith(NINResponseSchema)
@require_user
def add_nin(user, nin):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    current_app.logger.info('Removing NIN from user')
    current_app.logger.debug('NIN: {}'.format(nin))

    nin_obj = security_user.nins.find(nin)
    if nin_obj:
        current_app.logger.info('NIN already added.')
        return error_response(message=SecurityMsg.already_exists)

    try:
        nin_element = NinProofingElement.from_dict(dict(number=nin, created_by='security', verified=False))
        proofing_state = NinProofingState.from_dict(
            {'eduPersonPrincipalName': security_user.eppn, 'nin': nin_element.to_dict()}
        )
        add_nin_to_user(user, proofing_state, user_class=SecurityUser)
        return success_response(
            payload=dict(nins=security_user.nins.to_list_of_dicts()), message=SecurityMsg.add_success
        )
    except AmTaskFailed as e:
        current_app.logger.error('Adding nin to user failed')
        current_app.logger.debug(f'NIN: {nin}')
        current_app.logger.error('{}'.format(e))
        return error_response(message=CommonMsg.temp_problem)
