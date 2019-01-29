# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import, unicode_literals

import json
import base64
from flask import Blueprint, session, Response
from flask import current_app, request

from fido2.client import ClientData
from fido2.server import Fido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

from eduid_userdb.credentials import Webauthn
from eduid_userdb.security import SecurityUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.security.helpers import credentials_to_registered_keys, compile_credential_list
from eduid_webapp.security.schemas import WebauthnOptionsResponseSchema
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
        self.credential_id = id.encode('ascii')

def make_credentials(creds):
    return [Credential(cred.key) for cred in creds]


webauthn_views = Blueprint('webauthn', __name__, url_prefix='/webauthn', template_folder='templates')

@webauthn_views.route('/register/begin', methods=['GET'])
@MarshalWith(WebauthnOptionsResponseSchema)
@require_user
def registration_begin(user):
    user_webauthn_tokens = user.credentials.filter(Webauthn)
    if user_webauthn_tokens.count >= current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']:
        current_app.logger.error('User tried to register more than {} tokens.'.format(
            current_app.config['WEBAUTHN_MAX_ALLOWED_TOKENS']))
        resp = {'_status': 'error', 'message': 'security.webauthn.max_allowed_tokens'}
        cbor_resp = cbor.dumps(resp)
        return Response(response=cbor_resp, status=200, mimetype='application/cbor')
    creds = make_credentials(user_webauthn_tokens.to_list())
    server = get_webauthn_server()
    registration_data, state = server.register_begin({
        'id': str(user.user_id).encode('ascii'),
        'name': user.surname,
        'displayName': user.display_name,
        'icon': ''
    }, creds)
    session['_webauthn_state_'] = state

    current_app.logger.info('User {} has started registration of a webauthn token'.format(user))
    current_app.logger.debug('Webauthn Registration data: {}.'.format(registration_data))
    current_app.stats.count(name='webauthn_register_begin')

    cbor_data = cbor.dumps(registration_data)
    current_app.logger.debug('CBOR encoded Registration data: {}.'.format(cbor_data))
    return Response(response=cbor_data, status=200, mimetype='application/cbor')


@webauthn_views.route('/register/complete', methods=['POST'])
@MarshalWith(SecurityResponseSchema)
@require_user
def registration_complete(user):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    data = cbor.loads(request.data)[0]
    server = get_webauthn_server()

    current_app.logger.debug('Webauthn Registration data: {}.'.format(data))
    # csrf_token = data['csrf_token']
    description = data['description']
    credential_id = data['credentialId']
    attestation = data['attestationObject']
    att_obj = AttestationObject(attestation)
    client_data = ClientData(data['clientDataJSON'])
    state = session['_webauthn_state_']
    auth_data = server.register_complete(state, client_data, att_obj)

    credential = Webauthn(
        keyhandle = credential_id,
        public_key = str(auth_data.credential_data.public_key).replace('\\\\', '\\'),
        app_id = current_app.config['WEBAUTHN_RP_ID'],
        attest_obj = base64.b64encode(attestation).decode('ascii'),
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
