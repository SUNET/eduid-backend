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
#     3. Neither the name of the SUNET nor the names of its
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
from datetime import timedelta

from flask import Blueprint

from eduid.userdb import User
from eduid.userdb.credentials import Password
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.security import SecurityUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.utils import check_password_hash, get_zxcvbn_terms, hash_password, save_and_sync_user
from eduid.webapp.common.api.validation import is_valid_password
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.vccs import change_password
from eduid.webapp.common.session import session
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.helpers import (
    SecurityMsg,
    check_reauthn,
    compile_credential_list,
    generate_suggested_password,
)
from eduid.webapp.security.schemas import (
    ChangePasswordRequestSchema,
    SecurityResponseSchema,
    SuggestedPasswordResponseSchema,
)

change_password_views = Blueprint('change_password', __name__, url_prefix='/change-password')


@change_password_views.route('/suggested-password', methods=['GET'])
@MarshalWith(SuggestedPasswordResponseSchema)
@require_user
def get_suggested(user) -> FluxData:
    """
    View to get a suggested password for the logged user.
    """
    authn = session.authn.sp.get_authn_for_action(AuthnAcsAction.change_password)
    current_app.logger.debug(f'change_password called with authn {authn}')
    _need_reauthn = check_reauthn(authn, current_app.conf.chpass_reauthn_timeout)
    if _need_reauthn:
        return _need_reauthn

    current_app.logger.debug(f'Sending new generated password for {user}')
    password = generate_suggested_password()
    session.security.generated_password_hash = hash_password(password)
    return success_response(payload={'suggested_password': password}, message=None)


@change_password_views.route('/set-password', methods=['POST'])
@MarshalWith(SecurityResponseSchema)
@UnmarshalWith(ChangePasswordRequestSchema)
@require_user
def change_password_view(user: User, old_password: str, new_password: str) -> FluxData:
    """
    View to change the password
    """
    authn = session.authn.sp.get_authn_for_action(AuthnAcsAction.change_password)
    current_app.logger.debug(f'change_password called with authn {authn}')
    _need_reauthn = check_reauthn(authn, current_app.conf.chpass_reauthn_timeout)
    if _need_reauthn:
        return _need_reauthn

    if not new_password or (current_app.conf.chpass_old_password_needed and not old_password):
        return error_response(message=SecurityMsg.chpass_no_data)

    old_password_id = None
    if old_password is None:
        # Try to find the password credential that the user used for reauthn. That one should be revoked.
        # If we do not find it we will revoke all of the users passwords.
        for cred_id in authn.credentials_used:
            credential = user.credentials.find(cred_id)
            if isinstance(credential, Password):
                old_password_id = cred_id
                break
    try:
        is_valid_password(
            new_password,
            user_info=get_zxcvbn_terms(user),
            min_entropy=current_app.conf.password_entropy,
            min_score=current_app.conf.min_zxcvbn_score,
        )
    except ValueError:
        return error_response(message=SecurityMsg.chpass_weak)

    if check_password_hash(new_password, session.security.generated_password_hash):
        is_generated = True
        current_app.stats.count(name='change_password_generated_password_used')
    else:
        is_generated = False
        current_app.stats.count(name='change_password_custom_password_used')

    security_user = SecurityUser.from_user(user, current_app.private_userdb)

    added = change_password(
        user=security_user,
        new_password=new_password,
        old_password=old_password,
        old_password_id=old_password_id,
        application='security',
        is_generated=is_generated,
        vccs_url=current_app.conf.vccs_url,
    )

    if not added:
        current_app.logger.error(f'Could not verify the old password')
        return error_response(message=SecurityMsg.unrecognized_pw)
    try:
        save_and_sync_user(security_user)
    except UserOutOfSync:
        return error_response(message=CommonMsg.out_of_sync)

    current_app.stats.count(name='security_password_changed')
    current_app.logger.info(f'Changed password for user')

    return success_response(
        payload={'credentials': compile_credential_list(security_user)}, message=SecurityMsg.change_password_success,
    )
