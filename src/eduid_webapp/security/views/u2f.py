# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, session
from flask import current_app
from u2flib_server.u2f import begin_registration, begin_authentication, complete_registration, complete_authentication

from eduid_userdb.credentials import U2F
from eduid_userdb.security import SecurityUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.security.schemas import EnrollU2FTokenResponseSchema, BindU2FRequestSchema
from eduid_webapp.security.schemas import SignWithU2FTokenResponseSchema, VerifyWithU2FTokenRequestSchema
from eduid_webapp.security.schemas import VerifyWithU2FTokenResponseSchema, ModifyU2FTokenRequestSchema
from eduid_webapp.security.schemas import RemoveU2FTokenRequestSchema, SecurityResponseSchema
from eduid_webapp.security.helpers import credentials_to_registered_keys


__author__ = 'lundberg'


u2f_views = Blueprint('u2f', __name__, url_prefix='/u2f', template_folder='templates')


@u2f_views.route('/enroll', methods=['GET'])
@MarshalWith(EnrollU2FTokenResponseSchema)
@require_user
def enroll(user):
    user_u2f_tokens = user.credentials.filter(U2F)
    if user_u2f_tokens.count >= current_app.config['U2F_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['U2F_MAX_ALLOWED_TOKENS']))
        return {'_error': True, 'message': 'security.u2f.max_allowed_tokens'}
    registered_keys = credentials_to_registered_keys(user_u2f_tokens)
    enrollment = begin_registration(current_app.config['UF2_APP_ID'], registered_keys)
    session['_u2f_enroll_'] = enrollment.json
    current_app.stats.count(name='u2f_token_enroll')
    return enrollment.data_for_client


@u2f_views.route('/bind', methods=['POST'])
@UnmarshalWith(BindU2FRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def bind(user, version, registration_data, client_data, description=''):
    security_user = SecurityUser(data=user.to_dict())
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
                    public_key=device['publicKey'], attest_cert=cert, description=description,
                    application='eduid_security', created_ts=True)
    security_user.credentials.add(u2f_token)
    save_and_sync_user(security_user)
    current_app.stats.count(name='u2f_token_bind')
    return {
        'credentials': current_app.authninfo_db.get_authn_info(security_user)
    }


@u2f_views.route('/sign', methods=['GET'])
@MarshalWith(SignWithU2FTokenResponseSchema)
@require_user
def sign(user):
    user_u2f_tokens = user.credentials.filter(U2F)
    if not user_u2f_tokens.count:
        current_app.logger.error('Found no U2F token for user.')
        return {'_error': True, 'message': 'security.u2f.no_token_found'}
    registered_keys = credentials_to_registered_keys(user_u2f_tokens)
    challenge = begin_authentication(current_app.config['UF2_APP_ID'], registered_keys)
    session['_u2f_challenge_'] = challenge.json
    current_app.stats.count(name='u2f_sign')
    return challenge.data_for_client


@u2f_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerifyWithU2FTokenRequestSchema)
@MarshalWith(VerifyWithU2FTokenResponseSchema)
@require_user
def verify(user, key_handle, signature_data, client_data):
    challenge = session.pop('_u2f_challenge_')
    if not challenge:
        current_app.logger.error('Found no U2F challenge data in session.')
        return {'_error': True, 'message': 'security.u2f.missing_challenge_data'}
    data = {
        'keyHandle': key_handle,
        'signatureData': signature_data,
        'clientData': client_data
    }
    device, c, t = complete_authentication(challenge, data, [current_app.config['SERVER_NAME']])
    current_app.stats.count(name='u2f_verify')
    return {'keyHandle': device['keyHandle'], 'touch': t, 'counter': c}


@u2f_views.route('/modify', methods=['POST'])
@UnmarshalWith(ModifyU2FTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def modify(user, key_handle, description):
    security_user = SecurityUser(data=user.to_dict())
    token_to_modify = security_user.credentials.filter(U2F).find(key_handle)
    if not token_to_modify:
        current_app.logger.error('Did not find requested U2F token for user.')
        return {'_error': True, 'message': 'security.u2f.missing_u2f_token'}
    if len(description) > current_app.config['U2F_MAX_DESCRIPTION_LENGTH']:
        current_app.logger.error('User tried to set a U2F token description longer than {}.'.format(
            current_app.config['U2F_MAX_DESCRIPTION_LENGTH']))
        return {'_error': True, 'message': 'security.u2f.missing_u2f_token'}
    token_to_modify.description = description
    save_and_sync_user(security_user)
    current_app.stats.count(name='u2f_token_modify')


@u2f_views.route('/remove', methods=['POST'])
@UnmarshalWith(RemoveU2FTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def remove(user):
    current_app.stats.count(name='u2f_token_remove')
