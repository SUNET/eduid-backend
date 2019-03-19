# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import, unicode_literals

import base64
from flask import Blueprint
from flask import current_app

from fido2.client import ClientData
from fido2.server import Fido2Server, RelyingParty
from fido2.ctap2 import AttestationObject
from fido2 import cbor
from fido2.ctap2 import AttestedCredentialData

from eduid_userdb.credentials import Webauthn
# TODO: Import FidoCredential in eduid_userdb.credentials so we can import it from there
from eduid_userdb.credentials.fido import FidoCredential
from eduid_userdb.security import SecurityUser
from eduid_common.session import session
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.security.helpers import compile_credential_list
from eduid_webapp.security.schemas import WebauthnRegisterRequestSchema
from eduid_webapp.security.schemas import SecurityResponseSchema, RemoveWebauthnTokenRequestSchema
from eduid_webapp.security.schemas import VerifyWithWebauthnTokenRequestSchema
from eduid_webapp.security.schemas import VerifyWithWebauthnTokenResponseSchema


def get_webauthn_server(rp_id, name='eduID security API'):
    rp = RelyingParty(rp_id, name)
    return Fido2Server(rp)


def make_credentials(creds):
    credentials = []
    for cred in creds:
        cred_data = base64.urlsafe_b64decode(cred.credential_data.encode('ascii'))
        credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
        if rest:
            continue
        credentials.append(credential_data)
    return credentials


webauthn_views = Blueprint('webauthn', __name__, url_prefix='/webauthn', template_folder='templates')

@webauthn_views.route('/register/begin', methods=['GET'])
@MarshalWith(FluxStandardAction)
@require_user
def registration_begin(user):
    user_webauthn_tokens = user.credentials.filter(FidoCredential)
    if user_webauthn_tokens.count >= current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']))
        return {'_status': 'error', 'message': 'security.webauthn.max_allowed_tokens'}
    creds = make_credentials(user_webauthn_tokens.to_list())
    server = get_webauthn_server(current_app.config['FIDO2_RP_ID'])
    if user.given_name is None or user.surname is None or user.display_name is None:
        return {'_status': 'error', 'message': 'security.webauthn-missing-pdata'}
    registration_data, state = server.register_begin({
        'id': str(user.eppn).encode('ascii'),
        'name': "{} {}".format(user.given_name, user.surname),
        'displayName': user.display_name
    }, creds)
    session['_webauthn_state_'] = state

    current_app.logger.info('User {} has started registration of a webauthn token'.format(user))
    current_app.logger.debug('Webauthn Registration data: {}.'.format(registration_data))
    current_app.stats.count(name='webauthn_register_begin')

    encoded_data = base64.urlsafe_b64encode(cbor.dumps(registration_data)).decode('ascii')
    encoded_data = encoded_data.rstrip('=')
    return {
        'csrf_token': session.new_csrf_token(),
        'registration_data': encoded_data
    }


def urlsafe_b64decode(data):
    data += '=' * (len(data) % 4)
    return base64.urlsafe_b64decode(data)


@webauthn_views.route('/register/complete', methods=['POST'])
@UnmarshalWith(WebauthnRegisterRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def registration_complete(user, credential_id, attestation_object, client_data, description):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    server = get_webauthn_server(current_app.config['FIDO2_RP_ID'])

    att_obj = AttestationObject(urlsafe_b64decode(attestation_object))
    cdata_obj = ClientData(urlsafe_b64decode(client_data))
    state = session['_webauthn_state_']
    auth_data = server.register_complete(state, cdata_obj, att_obj)

    cred_data = auth_data.credential_data
    current_app.logger.debug('Proccessed Webauthn credential data: {}.'.format(cred_data))

    credential = Webauthn(
        keyhandle = credential_id,
        credential_data = base64.urlsafe_b64encode(cred_data).decode('ascii'),
        app_id = current_app.config['FIDO2_RP_ID'],
        attest_obj = base64.b64encode(attestation_object.encode('utf-8')).decode('ascii'),
        description = description,
        application = 'security'
        )

    security_user.credentials.add(credential)
    save_and_sync_user(security_user)
    current_app.stats.count(name='webauthn_register_complete')
    current_app.logger.info('User {} has completed registration of a webauthn token'.format(security_user))
    return {
        'message': 'security.webauthn_register_success',
        'credentials': compile_credential_list(security_user)
    }


@webauthn_views.route('/remove', methods=['POST'])
@UnmarshalWith(RemoveWebauthnTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def remove(user, credential_key):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    tokens = security_user.credentials.filter(FidoCredential)
    if tokens.count <= 1:
        return {'_error': True, 'message': 'security.webauthn-noremove-last'}
    token_to_remove = security_user.credentials.find(credential_key)
    if token_to_remove:
        security_user.credentials.remove(credential_key)
        save_and_sync_user(security_user)
        current_app.stats.count(name='webauthn_token_remove')
        current_app.logger.info(f'User {security_user} has removed a security token: {credential_key}')
        message = 'security.webauthn-token-removed'
    else:
        current_app.logger.info(f'User {security_user} has tried to remove a'
                                f' missing security token: {credential_key}')
        message = 'security.webauthn-token-notfound'
    return {
        'message': message,
        'credentials': compile_credential_list(security_user)
    }


@webauthn_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerifyWithWebauthnTokenRequestSchema)
@MarshalWith(VerifyWithWebauthnTokenResponseSchema)
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
    device, c, t = complete_authentication(challenge, data, current_app.config['U2F_FACETS'])
    current_app.stats.count(name='webauthn_verify')
    return {'key_handle': device['keyHandle'], 'counter': c, 'touch': t}
