# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import, unicode_literals

import json
from flask import Blueprint, session
from flask import current_app

from fido2.client import ClientData
from fido2.server import Fido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AuthenticatorData

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

from eduid_userdb.credentials import U2F
from eduid_userdb.security import SecurityUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.security.helpers import credentials_to_registered_keys, compile_credential_list
from eduid_webapp.security.schemas import BeginWebauthnRegistrationResponseSchema
from eduid_webapp.security.schemas import WebauthnBeginResponseSchema
from eduid_webapp.security.schemas import WebauthnAttestationRequestSchema
from eduid_webapp.security.schemas import SecurityResponseSchema


WEBAUTHN_SERVER = None

def update_webauthn_server(rp_id, name='eduID security API'):
    rp = RelyingParty(rp_id, name)
    server = Fido2Server(rp)
    global WEBAUTHN_SERVER
    WEBAUTHN_SERVER = server
    return server

def get_webauthn_server():
    if WEBAUTHN_SERVER is not None:
        return WEBAUTHN_SERVER
    return update_webauthn_server(current_app.config['WEBAUTHN_RP_ID'])


class Credential:
    def __init__(self, id):
        self.credential_id = id

def make_credentials(creds):
    return [Credential(cred.key) for cred in creds]


webauthn_views = Blueprint('webauthn', __name__, url_prefix='/webauthn', template_folder='templates')

@webauthn_views.route('/register/begin', methods=['POST'])
@MarshalWith(BeginWebauthnRegistrationResponseSchema)
@require_user
def registration_begin(user):
    user_webauthn_tokens = user.credentials.filter(U2F)
    if user_webauthn_tokens.count >= current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']))
        return {'_error': True, 'message': 'security.webauthn.max_allowed_tokens'}
    creds = make_credentials(user_webauthn_tokens.to_list())
    server = get_webauthn_server()
    registration_data, state = server.register_begin({
        'id': user.user_id,
        'name': user.surname,
        'displayName': user.display_name,
        'icon': ''
    }, creds)
    session['_webauthn_state_'] = state
    current_app.stats.count(name='webauthn_register_begin')
    return WebauthnBeginResponseSchema().load(registration_data).data


@webauthn_views.route('/register/complete', methods=['POST'])
@UnmarshalWith(WebauthnAttestationRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def registration_complete(user, attestation, client_data_json):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    server = get_webauthn_server(current_app.config['WEBAUTHN_RP_ID'])
    att_obj = AttestationObject(attestation)
    client_data = ClientData(client_data_json)
    state = session['_webauthn_state_']
    auth_data = server.register_complete(state, client_data, att_obj)
    security_user.credentials.add(auth_data.credential_data)
    save_and_sync_user(security_user)
    current_app.stats.count(name='webauthn_register_complete')
    return {
        'message': 'security.webauthn_register_success',
        'credentials': compile_credential_list(security_user)
    }
