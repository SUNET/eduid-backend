# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import base64

from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AttestedCredentialData
from fido2.server import USER_VERIFICATION, Fido2Server, RelyingParty
from flask import Blueprint

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.messages import error_response, success_response
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.utils import save_and_sync_user
from eduid_common.session import session
from eduid_userdb.credentials import Webauthn

# TODO: Import FidoCredential in eduid_userdb.credentials so we can import it from there
from eduid_userdb.credentials.fido import FidoCredential
from eduid_userdb.security import SecurityUser

from eduid_webapp.security.app import current_security_app as current_app
from eduid_webapp.security.helpers import SecurityMsg, compile_credential_list
from eduid_webapp.security.schemas import (
    RemoveWebauthnTokenRequestSchema,
    SecurityResponseSchema,
    WebauthnRegisterBeginSchema,
    WebauthnRegisterRequestSchema,
)


def get_webauthn_server(rp_id, name='eduID security API'):
    rp = RelyingParty(rp_id, name)
    return Fido2Server(rp)


def make_credentials(creds):
    credentials = []
    for cred in creds:
        if isinstance(cred, Webauthn):
            cred_data = base64.urlsafe_b64decode(cred.credential_data.encode('ascii'))
            credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
            if rest:
                continue
        else:
            # cred is of type U2F (legacy registration)
            credential_data = AttestedCredentialData.from_ctap1(
                cred.keyhandle.encode('ascii'), cred.public_key.encode('ascii')
            )
        credentials.append(credential_data)
    return credentials


webauthn_views = Blueprint('webauthn', __name__, url_prefix='/webauthn', template_folder='templates')


@webauthn_views.route('/register/begin', methods=['POST'])
@UnmarshalWith(WebauthnRegisterBeginSchema)
@MarshalWith(FluxStandardAction)
@require_user
def registration_begin(user, authenticator):
    user_webauthn_tokens = user.credentials.filter(FidoCredential)
    if user_webauthn_tokens.count >= current_app.config.webauthn_max_allowed_tokens:
        current_app.logger.error(
            'User tried to register more than {} tokens.'.format(current_app.config.webauthn_max_allowed_tokens)
        )
        return error_response(message=SecurityMsg.max_webauthn)

    creds = make_credentials(user_webauthn_tokens.to_list())
    server = get_webauthn_server(current_app.config.fido2_rp_id)
    if user.given_name is None or user.surname is None or user.display_name is None:
        return error_response(message=SecurityMsg.no_pdata)

    registration_data, state = server.register_begin(
        {
            'id': str(user.eppn).encode('ascii'),
            'name': "{} {}".format(user.given_name, user.surname),
            'displayName': user.display_name,
        },
        credentials=creds,
        user_verification=USER_VERIFICATION.DISCOURAGED,
        authenticator_attachment=authenticator,
    )
    session['_webauthn_state_'] = state

    current_app.logger.info('User {} has started registration of a webauthn token'.format(user))
    current_app.logger.debug('Webauthn Registration data: {}.'.format(registration_data))
    current_app.stats.count(name='webauthn_register_begin')

    encoded_data = base64.urlsafe_b64encode(cbor.encode(registration_data)).decode('ascii')
    encoded_data = encoded_data.rstrip('=')
    return {'csrf_token': session.new_csrf_token(), 'registration_data': encoded_data}


def urlsafe_b64decode(data):
    data += '=' * (len(data) % 4)
    return base64.urlsafe_b64decode(data)


@webauthn_views.route('/register/complete', methods=['POST'])
@UnmarshalWith(WebauthnRegisterRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def registration_complete(user, credential_id, attestation_object, client_data, description):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    server = get_webauthn_server(current_app.config.fido2_rp_id)
    att_obj = AttestationObject(urlsafe_b64decode(attestation_object))
    cdata_obj = ClientData(urlsafe_b64decode(client_data))
    state = session['_webauthn_state_']
    auth_data = server.register_complete(state, cdata_obj, att_obj)

    cred_data = auth_data.credential_data
    current_app.logger.debug('Proccessed Webauthn credential data: {}.'.format(cred_data))

    credential = Webauthn.from_dict(
        dict(
            keyhandle=credential_id,
            credential_data=base64.urlsafe_b64encode(cred_data).decode('ascii'),
            app_id=current_app.config.fido2_rp_id,
            attest_obj=base64.b64encode(attestation_object.encode('utf-8')).decode('ascii'),
            description=description,
            created_by='security',
        )
    )

    security_user.credentials.add(credential)
    save_and_sync_user(security_user)
    current_app.stats.count(name='webauthn_register_complete')
    current_app.logger.info('User {} has completed registration of a webauthn token'.format(security_user))
    credentials = compile_credential_list(security_user)
    return success_response(payload=dict(credentials=credentials), message=SecurityMsg.webauthn_success)


@webauthn_views.route('/remove', methods=['POST'])
@UnmarshalWith(RemoveWebauthnTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def remove(user, credential_key):
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    tokens = security_user.credentials.filter(FidoCredential)
    if tokens.count <= 1:
        return {'_error': True, 'message': SecurityMsg.no_last.value}

    token_to_remove = security_user.credentials.find(credential_key)
    if token_to_remove:
        security_user.credentials.remove(credential_key)
        save_and_sync_user(security_user)
        current_app.stats.count(name='webauthn_token_remove')
        current_app.logger.info(f'User {security_user} has removed a security token: {credential_key}')
        message = SecurityMsg.rm_webauthn
    else:
        current_app.logger.info(
            f'User {security_user} has tried to remove a' f' missing security token: {credential_key}'
        )
        message = SecurityMsg.no_webauthn

    credentials = compile_credential_list(security_user)
    return {'message': message, 'credentials': credentials}
