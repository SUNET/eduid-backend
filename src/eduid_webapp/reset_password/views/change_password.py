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
from datetime import datetime

from flask import Blueprint

from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.reset_password import ResetPasswordUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_common.authn.vccs import change_password
from eduid_common.session import session
from eduid_webapp.security.schemas import CredentialList
from eduid_webapp.reset_password.helpers import compile_credential_list
from eduid_webapp.reset_password.helpers import generate_suggested_password
from eduid_webapp.reset_password.helpers import hash_password, check_password
from eduid_webapp.reset_password.helpers import ResetPwMsg
from eduid_webapp.reset_password.schemas import ChangePasswordSchema
from eduid_webapp.reset_password.schemas import ChpassResponseSchema
from eduid_webapp.reset_password.schemas import SuggestedPassword, SuggestedPasswordResponseSchema
from eduid_webapp.reset_password.helpers import error_message
from eduid_webapp.reset_password.app import current_reset_password_app as current_app

change_password_views = Blueprint('change_password', __name__, url_prefix='')


@change_password_views.route('/suggested-password', methods=['GET'])
@MarshalWith(SuggestedPasswordResponseSchema)
@require_user
def get_suggested(user):
    """
    View to get a suggested  password for the logged user.
    """
    current_app.logger.debug(f'Sending new generated password for {user}')
    password = generate_suggested_password()

    session.reset_password.generated_password_hash = hash_password(password)

    suggested = {
            'suggested_password': password
            }

    return SuggestedPassword().dump(suggested).data


@change_password_views.route('/change-password', methods=['POST'])
@MarshalWith(ChpassResponseSchema)
@UnmarshalWith(ChangePasswordSchema)
@require_user
def change_password_view(user, old_password, new_password):
    """
    View to change the password
    """
    resetpw_user = ResetPasswordUser.from_user(user, current_app.private_userdb)
    authn_ts = session.get('reauthn-for-chpass', None)
    if authn_ts is None:
        return error_message(ResetPwMsg.no_reauthn)

    now = datetime.utcnow()
    delta = now - datetime.fromtimestamp(authn_ts)
    timeout = current_app.config.chpass_timeout
    if int(delta.total_seconds()) > timeout:
        return error_message(ResetPwMsg.stale_reauthn)

    hashed = session.reset_password.generated_password_hash
    if check_password(new_password, hashed):
        is_generated = True
        current_app.stats.count(name='change_password_generated_password_used')
    else:
        is_generated = False
        current_app.stats.count(name='change_password_custom_password_used')

    vccs_url = current_app.config.vccs_url
    added = change_password(resetpw_user, new_password, old_password,
                            'security', is_generated, vccs_url)

    if not added:
        current_app.logger.debug(f'Problem verifying the old credentials for {user}')
        return error_message(ResetPwMsg.unrecognized_pw)

    resetpw_user.terminated = False
    try:
        save_and_sync_user(resetpw_user)
    except UserOutOfSync:
        return error_message(ResetPwMsg.out_of_sync)

    del session['reauthn-for-chpass']

    current_app.stats.count(name='security_password_changed', value=1)
    current_app.logger.info(f'Changed password for user {resetpw_user.eppn}')

    next_url = current_app.config.dashboard_url
    credentials = {
        'next_url': next_url,
        'credentials': compile_credential_list(resetpw_user),
        'message': 'chpass.password-changed'
        }

    return CredentialList().dump(credentials).data
