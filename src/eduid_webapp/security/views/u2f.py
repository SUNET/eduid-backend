# -*- coding: utf-8 -*-

from __future__ import absolute_import
from datetime import datetime
from urllib import urlencode
import urlparse

from flask import Blueprint, session, abort, url_for, redirect
from flask import render_template, current_app
from u2flib_server.u2f import begin_registration, begin_authentication, complete_registration, complete_authentication

from eduid_userdb.u2f import U2F, u2f_from_dict
from eduid_userdb.exceptions import UserOutOfSync
from eduid_common.api.utils import urlappend
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_common.authn.utils import generate_password
from eduid_common.authn.vccs import add_credentials, revoke_all_credentials
from eduid_webapp.security.schemas import EnrollU2FTokenResponseSchema, BindU2FRequestSchema
from eduid_webapp.security.schemas import SignWithU2FTokenResponseSchema, VerifyWithU2FTokenRequestSchema
from eduid_webapp.security.schemas import VerifyWithU2FTokenResponseSchema, ModifyU2FTokenRequestSchema
from eduid_webapp.security.schemas import RemoveU2FTokenRequestSchema, SecurityResponseSchema


__author__ = 'lundberg'


u2f_views = Blueprint('u2f', __name__, url_prefix='/u2f', template_folder='templates')


@u2f_views.route('/enroll', methods=['GET'])
@MarshalWith(EnrollU2FTokenResponseSchema)
@require_dashboard_user
def enroll(user):
    existing_u2f_tokens = user.credentials.filter(U2F).to_list()
    if len(existing_u2f_tokens) >= current_app.config['U2F_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['U2F_MAX_ALLOWED_TOKENS']))
        return {'_error': True, 'message': 'security.u2f.max_allowed_tokens'}
    enrollment = begin_registration(current_app.config['UF2_APP_ID'], existing_u2f_tokens)
    session['_u2f_enroll_'] = enrollment.json

    return enrollment.data_for_client


@u2f_views.route('/bind', methods=['POST'])
@UnmarshalWith(BindU2FRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_dashboard_user
def bind(user, version, registration_data, client_data):
    enrollment_data = session.pop('_u2f_enroll_', None)
    if not enrollment_data:
        current_app.logger.error('Found no U2F enrollment data in session.')
        return {'_error': True, 'message': 'security.u2f.missing_enrollment_data'}
    data = {
        'version': version,
        'registrationData': registration_data,
        'clientData': client_data
    }
    device, cert = complete_registration(enrollment_data, data, [current_app.config['SERVER_NAME']])
    u2f_token = U2F(version=device['version'], keyhandle=device['keyHandle'], app_id=device['appId'],
                    public_key=device['publicKey'], attest_cert=cert, application='eduid_security', created_ts=True)
    user.credentials.add(u2f_token)
    save_dashboard_user(user)
    return {
        'credentials': current_app.authninfo_db.get_authn_info(user)
    }


@u2f_views.route('/sign', methods=['GET'])
@MarshalWith(SignWithU2FTokenResponseSchema)
@require_dashboard_user
def sign(user):
    pass


@u2f_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerifyWithU2FTokenRequestSchema)
@MarshalWith(VerifyWithU2FTokenResponseSchema)
@require_dashboard_user
def verify(user):
    pass


@u2f_views.route('/modify', methods=['POST'])
@UnmarshalWith(ModifyU2FTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_dashboard_user
def modify(user):
    pass


@u2f_views.route('/remove', methods=['POST'])
@UnmarshalWith(RemoveU2FTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_dashboard_user
def remove(user):
    pass
