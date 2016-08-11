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

from flask import json
from flask import Blueprint, current_app, request, abort

from eduid_userdb.exceptions import UserOutOfSync
from eduid_common.api.decorators import require_dashboard_user
from eduid_common.api.utils import save_dashboard_user
from eduid_webapp.personal_data.schemas import PersonalDataSchema

pd_views = Blueprint('personal_data', __name__, url_prefix='')


@pd_views.route('/user', methods=['GET', 'POST'])
@require_dashboard_user
def user(user):
    if request.method == 'POST':
        data = json.loads(request.get_data())
        schema = PersonalDataSchema().load(data)
        if not schema.errors:
            user.given_name = schema.data['given_name']
            user.surname = schema.data['surname']
            user.display_name = schema.data['display_name']
            user.language = schema.data['language']
            try:
                save_dashboard_user(user)
            except UserOutOfSync:
                return json.jsonify({
                    'type': 'POST_USERDATA_FAIL',
                    'error': {'form': 'user-out-of-sync'},
                    })
            return json.jsonify({
                'type': 'POST_USERDATA_SUCCESS',
                })
        return json.jsonify({
            'type': 'POST_USERDATA_FAIL',
            'error': schema.errors,
            })
    elif request.method == 'GET':
        schema = PersonalDataSchema().dump(user)
        return json.jsonify({
                'type': 'GET_USERDATA_SUCCESS',
                'payload': schema.data,
                })
