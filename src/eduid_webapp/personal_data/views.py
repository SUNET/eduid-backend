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

from flask import Blueprint

from eduid_userdb.exceptions import UserOutOfSync
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_webapp.personal_data.schemas import PersonalDataSchema, PersonalDataResponseSchema

pd_views = Blueprint('personal_data', __name__, url_prefix='')


@pd_views.route('/user', methods=['GET'])
@MarshalWith(PersonalDataResponseSchema)
@require_dashboard_user
def get_user(user):
    return PersonalDataSchema().dump(user).data


@pd_views.route('/user', methods=['POST'])
@UnmarshalWith(PersonalDataSchema)
@MarshalWith(PersonalDataResponseSchema)
@require_dashboard_user
def post_user(user, given_name, surname, display_name, language):
    user.given_name = given_name
    user.surname = surname
    user.display_name = display_name
    user.language = language
    try:
        save_dashboard_user(user)
    except UserOutOfSync:
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    return PersonalDataSchema().dump(user).data
