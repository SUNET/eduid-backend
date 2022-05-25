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
from datetime import timedelta
from typing import Dict
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from flask import Blueprint, redirect, request, url_for
from marshmallow import ValidationError

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import AmTaskFailed, MsgTaskFailed
from eduid.common.utils import urlappend
from eduid.userdb import User
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.proofing import NinProofingElement
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.security import SecurityUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.helpers import add_nin_to_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import get_zxcvbn_terms, save_and_sync_user
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.vccs import add_credentials, revoke_all_credentials
from eduid.webapp.common.session import session
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.helpers import (
    SecurityMsg,
    check_reauthn,
    compile_credential_list,
    generate_suggested_password,
    remove_nin_from_user,
    send_termination_mail,
    update_user_official_name,
)
from eduid.webapp.security.schemas import (
    AccountTerminatedSchema,
    ChangePasswordSchema,
    ChpassResponseSchema,
    IdentitiesResponseSchema,
    NINRequestSchema,
    RedirectResponseSchema,
    SecurityResponseSchema,
    SuggestedPasswordResponseSchema,
    UserUpdateResponseSchema,
)

security_views = Blueprint('security', __name__, url_prefix='', template_folder='templates')


@security_views.route('/credentials', methods=['GET'])
@MarshalWith(SecurityResponseSchema)
@require_user
def get_credentials(user):
    """
    View to get credentials for the logged user.
    """
    current_app.logger.debug(f'Trying to get the credentials for user {user}')

    credentials = {'credentials': compile_credential_list(user)}

    return credentials


# TODO: Remove this when removing change_password below
@security_views.route('/suggested-password', methods=['GET'])
@MarshalWith(SuggestedPasswordResponseSchema)
@require_user
def get_suggested(user):
    """
    View to get a suggested  password for the logged user.
    """
    current_app.logger.debug(f'Trying to get the credentials for user {user}')
    suggested = {'suggested_password': generate_suggested_password()}

    return suggested


# TODO: Remove this when frontend for new change password view exist
@security_views.route('/change-password', methods=['POST'])
@MarshalWith(ChpassResponseSchema)
@require_user
def change_password(user):
    """
    View to change the password
    """
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    current_app.logger.debug(f'change_password called for user {user}')

    schema = ChangePasswordSchema(
        zxcvbn_terms=get_zxcvbn_terms(security_user),
        min_entropy=current_app.conf.password_entropy,
        min_score=current_app.conf.min_zxcvbn_score,
    )

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

    authn = session.authn.sp.get_authn_for_action(AuthnAcsAction.change_password)
    current_app.logger.debug(f'change_password called for user {user}, authn {authn}')

    _need_reauthn = check_reauthn(authn, current_app.conf.chpass_reauthn_timeout)
    if _need_reauthn:
        return _need_reauthn

    vccs_url = current_app.conf.vccs_url
    added = add_credentials(old_password, new_password, security_user, source='security', vccs_url=vccs_url)

    if not added:
        current_app.logger.debug(f'Problem verifying the old credentials for {user}')
        return error_response(message='chpass.unable-to-verify-old-password')

    security_user.terminated = None
    try:
        save_and_sync_user(security_user)
    except UserOutOfSync:
        return error_response(message='user-out-of-sync')

    # del session['reauthn-for-chpass']

    current_app.stats.count(name='security_password_changed', value=1)
    current_app.logger.info('Changed password for user {}'.format(security_user.eppn))

    next_url = current_app.conf.dashboard_url
    credentials = {
        'next_url': next_url,
        'credentials': compile_credential_list(security_user),
        'message': SecurityMsg.chpass_password_changed2.value,
    }

    return credentials


@security_views.route('/terminate-account', methods=['POST'])
@MarshalWith(RedirectResponseSchema)
@UnmarshalWith(EmptyRequest)
@require_user
def delete_account(user: User):
    """
    Terminate account view.
    It receives a POST request, checks the csrf token,
    schedules the account termination action,
    and redirects to the IdP.
    """
    current_app.logger.debug('Initiating account termination for user')

    ts_url = current_app.conf.token_service_url
    terminate_url = urlappend(ts_url, 'terminate')
    next_url = url_for('security.account_terminated')

    params = {'next': next_url}

    url_parts = list(urlparse(terminate_url))
    query: Dict = parse_qs(url_parts[4])
    query.update(params)

    url_parts[4] = urlencode(query)
    location = urlunparse(url_parts)
    return {'location': location}


@security_views.route('/account-terminated', methods=['GET'])
@MarshalWith(AccountTerminatedSchema)
@require_user
def account_terminated(user: User):
    """
    The account termination action,
    removes all credentials for the terminated account
    from the VCCS service,
    flags the account as terminated,
    sends an email to the address in the terminated account,
    and logs out the session.
    """
    security_user = SecurityUser.from_user(user, current_app.private_userdb)

    authn = session.authn.sp.get_authn_for_action(AuthnAcsAction.terminate_account)
    current_app.logger.debug(f'account_terminated called with authn {authn}')
    # TODO: 10 minutes to complete account termination seems overly generous
    _need_reauthn = check_reauthn(authn, timedelta(seconds=600))
    if _need_reauthn:
        return _need_reauthn

    # revoke all user passwords
    revoke_all_credentials(security_user, vccs_url=current_app.conf.vccs_url)
    # Skip removing old passwords from the user at this point as a password reset will do that anyway.
    # This fixes the problem with loading users for a password reset as users without passwords triggers
    # the UserHasNotCompletedSignup check in eduid-userdb.
    # TODO: Needs a decision on how to handle unusable user passwords
    # for p in security_user.credentials.filter(Password).to_list():
    #    security_user.passwords.remove(p.key)

    # flag account as terminated
    security_user.terminated = utc_now()
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
    return redirect(f'{current_app.conf.logout_endpoint}?next={current_app.conf.termination_redirect_url}')


@security_views.route('/add-nin', methods=['POST'])
@UnmarshalWith(NINRequestSchema)
@MarshalWith(IdentitiesResponseSchema)
@require_user
def add_nin(user: User, nin: str) -> FluxData:
    current_app.logger.info('Adding NIN to user')
    current_app.logger.debug('NIN: {}'.format(nin))

    if user.identities.nin is not None:
        current_app.logger.info('NIN already added.')
        return error_response(message=SecurityMsg.already_exists)

    nin_element = NinProofingElement(number=nin, created_by='security', is_verified=False)
    proofing_state = NinProofingState(id=None, eppn=user.eppn, nin=nin_element, modified_ts=None)

    try:
        security_user = add_nin_to_user(user, proofing_state, user_type=SecurityUser)
    except AmTaskFailed:
        current_app.logger.exception('Adding nin to user failed')
        current_app.logger.debug(f'NIN: {nin}')
        return error_response(message=CommonMsg.temp_problem)

    # TODO: remove nins after frontend stops using it
    nins = []
    if security_user.identities.nin is not None:
        nins.append(security_user.identities.nin.to_old_nin())

    return success_response(
        payload=dict(identities=security_user.identities.to_list_of_dicts(), nins=nins), message=SecurityMsg.add_success
    )


@security_views.route('/remove-nin', methods=['POST'])
@UnmarshalWith(NINRequestSchema)
@MarshalWith(IdentitiesResponseSchema)
@require_user
def remove_nin(user: User, nin: str) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    current_app.logger.info('Removing NIN from user')
    current_app.logger.debug('NIN: {}'.format(nin))

    if user.identities.nin is not None:
        if user.identities.nin.number != nin:
            return success_response(
                payload=dict(identities=security_user.identities.to_list_of_dicts()), message=SecurityMsg.rm_success
            )

        if user.identities.nin.is_verified:
            current_app.logger.info('NIN verified. Will not remove it.')
            return error_response(message=SecurityMsg.rm_verified)

        try:
            remove_nin_from_user(security_user, user.identities.nin)
        except AmTaskFailed:
            current_app.logger.exception('Removing nin from user failed')
            current_app.logger.debug(f'NIN: {nin}')
            return error_response(message=CommonMsg.temp_problem)

    # TODO: remove nins after frontend stops using it
    nins = []
    if security_user.identities.nin is not None:
        nins.append(security_user.identities.nin.to_old_nin())

    return success_response(
        payload=dict(identities=security_user.identities.to_list_of_dicts(), nins=nins), message=SecurityMsg.rm_success
    )


@security_views.route('/refresh-official-user-data', methods=['POST'])
@UnmarshalWith(EmptyRequest)
@MarshalWith(UserUpdateResponseSchema)
@require_user
def refresh_user_data(user: User) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    if security_user.identities.nin is None or security_user.identities.nin.is_verified is False:
        return error_response(message=SecurityMsg.user_not_verified)

    current_app.stats.count(name='refresh_user_data_called')
    # only allow a user to request another update after throttle_update_user_period
    if session.security.user_requested_update is not None:
        retry_at = session.security.user_requested_update + current_app.conf.throttle_update_user_period
        if utc_now() < retry_at:
            return error_response(message=SecurityMsg.user_update_throttled)
    session.security.user_requested_update = utc_now()

    # Lookup person data via Navet
    current_app.logger.info('Getting Navet data for user')
    current_app.logger.debug(f'NIN: {security_user.identities.nin.number}')
    navet_data = current_app.msg_relay.get_all_navet_data(security_user.identities.nin.number)
    current_app.logger.debug(f'Navet data: {navet_data}')

    if navet_data.person.name.given_name is None or navet_data.person.name.surname is None:
        current_app.logger.info('Navet data incomplete for user')
        current_app.logger.debug(
            f'_given_name: {navet_data.person.name.given_name}, _surname: {navet_data.person.name.surname}'
        )
        current_app.stats.count(name='refresh_user_data_navet_data_incomplete')
        return error_response(message=SecurityMsg.navet_data_incomplete)

    # Update user official names if they differ
    if not update_user_official_name(security_user, navet_data):
        return error_response(message=CommonMsg.temp_problem)

    return success_response(message=SecurityMsg.user_updated)
