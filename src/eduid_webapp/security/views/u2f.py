# -*- coding: utf-8 -*-

from __future__ import absolute_import
from datetime import datetime
from urllib import urlencode
import urlparse

from flask import Blueprint, session, abort, url_for, redirect
from flask import render_template, current_app
from u2flib_server.u2f import begin_registration, begin_authentication, complete_registration, complete_authentication

from eduid_userdb.u2f import U2F
from eduid_userdb.exceptions import UserOutOfSync
from eduid_common.api.utils import urlappend
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_common.authn.utils import generate_password
from eduid_common.authn.vccs import add_credentials, revoke_all_credentials
from eduid_webapp.security.schemas import U2FEnrollResponseSchema, U2FBindRequestSchema, CredentialList
from eduid_webapp.security.schemas import U2FSignResponseSchema, U2FVerifyRequestSchema, U2FVerifyResponseSchema
from eduid_webapp.security.schemas import U2FModifyRequestSchema


__author__ = 'lundberg'


u2f_views = Blueprint('u2f', __name__, url_prefix='/u2f', template_folder='templates')


@u2f_views.route('/enroll', methods=['GET'])
@MarshalWith(U2FEnrollResponseSchema)
@require_dashboard_user
def enroll(user):
    existing_u2f_tokens = [item for item in user.credentials.to_list() if isinstance(item, U2F)]
    if len(existing_u2f_tokens) >= current_app.config['U2F_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['U2F_MAX_ALLOWED_TOKENS']))
        return {'_error': True, 'message': 'security.u2d.max_allowed_tokens'}
    enrollment = begin_registration(current_app.config['UF2_APP_ID'], existing_u2f_tokens)
    session['_u2f_enroll_'] = enrollment.json

    return enrollment.data_for_client


@u2f_views.route('/bind', methods=['POST'])
@UnmarshalWith(U2FBindRequestSchema)
@MarshalWith(CredentialList)
@require_dashboard_user
def bind(user):
    enroll = user.pop('_u2f_enroll_')
    data = {}
    device, cert = complete_registration(enroll, data, [self.facet])


@u2f_views.route('/sign', methods=['GET'])
@MarshalWith(U2FSignResponseSchema)
@require_dashboard_user
def sign(user):
    pass


@u2f_views.route('/verify', methods=['POST'])
@UnmarshalWith(U2FVerifyRequestSchema)
@MarshalWith(U2FVerifyResponseSchema)
@require_dashboard_user
def verify(user):
    pass


@u2f_views.route('/modify', methods=['POST'])
@UnmarshalWith(U2FModifyRequestSchema)
@MarshalWith(CredentialList)
@require_dashboard_user
def modify(user):
    pass


@u2f_views.route('/remove', methods=['POST'])
@MarshalWith(CredentialList)
@require_dashboard_user
def remove(user):
    pass
