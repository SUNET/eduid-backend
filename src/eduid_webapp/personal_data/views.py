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

from flask import Blueprint, current_app

from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.personal_data import PersonalDataUser
from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.personal_data.schemas import PersonalDataResponseSchema
from eduid_webapp.personal_data.schemas import PersonalDataRequestSchema
from eduid_webapp.personal_data.schemas import PersonalDataSchema
from eduid_webapp.personal_data.schemas import NinListSchema, NinsResponseSchema
from eduid_webapp.personal_data.schemas import AllDataResponseSchema, AllDataSchema

pd_views = Blueprint('personal_data', __name__, url_prefix='')


@pd_views.route('/all-user-data', methods=['GET'])
@MarshalWith(AllDataResponseSchema)
@require_user
def get_all_data(user):
    return AllDataSchema().dump(user.to_dict()).data


@pd_views.route('/user', methods=['GET'])
@MarshalWith(PersonalDataResponseSchema)
@require_user
def get_user(user):

    data = {
        'given_name': user.given_name,
        'surname': user.surname,
        'display_name': user.display_name,
        'language': user.language
    }

    return PersonalDataRequestSchema().dump(data).data


@pd_views.route('/user', methods=['POST'])
@UnmarshalWith(PersonalDataRequestSchema)
@MarshalWith(PersonalDataResponseSchema)
@require_user
def post_user(user, given_name, surname, display_name, language):
    personal_data_user = PersonalDataUser(data=user.to_dict())
    current_app.logger.debug('Trying to save user {!r}'.format(user))

    personal_data_user.given_name = given_name
    personal_data_user.surname = surname
    personal_data_user.display_name = display_name
    personal_data_user.language = language
    try:
        save_and_sync_user(personal_data_user)
    except UserOutOfSync:
        return {
            '_status': 'error',
            'message': 'user-out-of-sync'
        }
    current_app.stats.count(name='personal_data_saved', value=1)
    current_app.logger.info('Saved personal data for user {!r}'.format(personal_data_user))

    data = personal_data_user.to_dict()
    data['message'] = 'pd.save-success'
    return PersonalDataSchema().dump(data).data


@pd_views.route('/nins', methods=['GET'])
@MarshalWith(NinsResponseSchema)
@require_user
def get_nins(user):

    data = {
        'nins': user.nins.to_list_of_dicts()
    }

    return NinListSchema().dump(data).data
