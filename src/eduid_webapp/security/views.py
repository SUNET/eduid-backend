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

from flask import Blueprint, session, abort, current_app

from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_webapp.security.schemas import SecurityResponseSchema, CredentialList, CsrfSchema, SecurityPasswordSchema

security_views = Blueprint('security', __name__, url_prefix='', template_folder='templates')


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
    credentials =  { 'csrf_token': csrf_token,
        'credentials': current_app.authninfo_db.get_authn_info(user) }

    return CredentialList().dump(credentials).data


@security_views.route('/delete', methods=['POST'])
@UnmarshalWith(CsrfSchema)
@require_dashboard_user
def delete_account(user, csrf_token):
    """
    view to delete user account.
    """
    if session.get_csrf_token() != csrf_token:
        abort(400)

    current_app.logger.debug('Deleting account for user {!r}'.format(user))

    current_app.logger.info('Deleted account for user {!r}'.format(user))
    current_app.statsd.count(name='security_delete', value=1)

    return 200


@security_views.route('/new', methods=['POST'])
@UnmarshalWith(SecurityPasswordSchema)
@require_dashboard_user
def new_password(user, csrf_token, old_password, new_password):
    """
    view to change the password for user logged.
    """
    if session.get_csrf_token() != csrf_token:
        abort(400)

    current_app.logger.debug('Try to change password for user {!r}'.format(user))

    current_app.logger.info('Changed password for user {!r}'.format(user))
    current_app.statsd.count(name='security_new_password', value=1)

    return 200
