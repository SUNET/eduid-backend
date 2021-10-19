# -*- coding: utf-8 -*-

import base64
from typing import List, Optional, Sequence, Union

from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AttestedCredentialData
from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import UserVerificationRequirement
from flask import Blueprint

from eduid.userdb import User
from eduid.userdb.credentials import Webauthn
from eduid.userdb.credentials.fido import U2F, FidoCredential
from eduid.userdb.security import SecurityUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import WebauthnAuthenticator, WebauthnRegistration
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.helpers import SecurityMsg, compile_credential_list
from eduid.webapp.security.schemas import (
    RemoveWebauthnTokenRequestSchema,
    SecurityResponseSchema,
    WebauthnRegisterBeginSchema,
    WebauthnRegisterRequestSchema,
)
from eduid.webapp.security.settings.common import WebauthnAttestation


def get_webauthn_server(
    rp_id: str, name='eduID security API', attestation: Optional[WebauthnAttestation] = None
) -> Fido2Server:
    rp = PublicKeyCredentialRpEntity(rp_id, name)
    _att = None
    if attestation:
        _att = attestation.value()
    return Fido2Server(rp, attestation=_att)


def make_credentials(creds: Sequence[FidoCredential]) -> List[AttestedCredentialData]:
    credentials = []
    for cred in creds:
        if isinstance(cred, Webauthn):
            cred_data = base64.urlsafe_b64decode(cred.credential_data.encode('ascii'))
            credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
            if rest:
                continue
        elif isinstance(cred, U2F):
            # cred is of type U2F (legacy registration)
            credential_data = AttestedCredentialData.from_ctap1(
                cred.keyhandle.encode('ascii'), cred.public_key.encode('ascii')
            )
        else:
            raise ValueError(f'Unknown credential {repr(cred)}')
        credentials.append(credential_data)
    return credentials


webauthn_views = Blueprint('webauthn', __name__, url_prefix='/webauthn', template_folder='templates')


@webauthn_views.route('/register/begin', methods=['POST'])
@UnmarshalWith(WebauthnRegisterBeginSchema)
@MarshalWith(FluxStandardAction)
@require_user
def registration_begin(user: User, authenticator: str) -> FluxData:
    try:
        _auth_enum = WebauthnAuthenticator(authenticator)
    except ValueError:
        return error_response(message=SecurityMsg.invalid_authenticator)
    user_webauthn_tokens = user.credentials.filter(FidoCredential)
    if len(user_webauthn_tokens) >= current_app.conf.webauthn_max_allowed_tokens:
        current_app.logger.error(
            'User tried to register more than {} tokens.'.format(current_app.conf.webauthn_max_allowed_tokens)
        )
        return error_response(message=SecurityMsg.max_webauthn)

    creds = make_credentials(user_webauthn_tokens)
    server = get_webauthn_server(current_app.conf.fido2_rp_id, attestation=current_app.conf.webauthn_attestation)
    if user.given_name is None or user.surname is None or user.display_name is None:
        return error_response(message=SecurityMsg.no_pdata)

    registration_data, state = server.register_begin(
        {
            'id': str(user.eppn).encode('ascii'),
            'name': "{} {}".format(user.given_name, user.surname),
            'displayName': user.display_name,
        },
        credentials=creds,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        authenticator_attachment=_auth_enum.value,
    )
    session.security.webauthn_registration = WebauthnRegistration(webauthn_state=state, authenticator=_auth_enum)

    current_app.logger.info('User {} has started registration of a webauthn token'.format(user))
    current_app.logger.debug('Webauthn Registration data: {}.'.format(registration_data))
    current_app.stats.count(name='webauthn_register_begin')

    encoded_data = base64.urlsafe_b64encode(cbor.encode(registration_data)).decode('ascii')
    encoded_data = encoded_data.rstrip('=')
    return success_response({'csrf_token': session.new_csrf_token(), 'registration_data': encoded_data})


def urlsafe_b64decode(data: str) -> bytes:
    data += '=' * (len(data) % 4)
    return base64.urlsafe_b64decode(data)


@webauthn_views.route('/register/complete', methods=['POST'])
@UnmarshalWith(WebauthnRegisterRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def registration_complete(
    user: User, credential_id: str, attestation_object: str, client_data: str, description: str
) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    server = get_webauthn_server(current_app.conf.fido2_rp_id)
    att_obj = AttestationObject(urlsafe_b64decode(attestation_object))
    cdata_obj = ClientData(urlsafe_b64decode(client_data))
    if not session.security.webauthn_registration:
        current_app.logger.info('Found no webauthn registration state in the session')
        return error_response(message=SecurityMsg.missing_registration_state)
    # Move registration state from session to local variable to let users restart if something fails
    reg_state = session.security.webauthn_registration
    session.security.webauthn_registration = None
    auth_data = server.register_complete(reg_state.webauthn_state, cdata_obj, att_obj)

    cred_data = auth_data.credential_data
    current_app.logger.debug(f'Processed Webauthn credential data: {cred_data}')

    credential = Webauthn(
        keyhandle=credential_id,
        credential_data=base64.urlsafe_b64encode(cred_data).decode('ascii'),
        app_id=current_app.conf.fido2_rp_id,
        attest_obj=base64.b64encode(attestation_object.encode('utf-8')).decode('ascii'),
        description=description,
        created_by='security',
        authenticator=reg_state.authenticator,
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
def remove(user: User, credential_key: str) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    tokens = security_user.credentials.filter(FidoCredential)
    if len(tokens) <= 1:
        current_app.logger.info(f'User {security_user} has tried to remove the last security token')
        return error_response(message=SecurityMsg.no_last)

    token_to_remove = security_user.credentials.find(credential_key)
    if token_to_remove:
        security_user.credentials.remove(token_to_remove.key)
        save_and_sync_user(security_user)
        current_app.stats.count(name='webauthn_token_remove')
        current_app.logger.info(f'User {security_user} has removed a security token: {credential_key}')
        message = SecurityMsg.rm_webauthn
    else:
        current_app.logger.info(f'User {security_user} has tried to remove a missing security token: {credential_key}')
        return error_response(message=SecurityMsg.no_webauthn)

    credentials = compile_credential_list(security_user)
    return success_response(message=message, payload={'credentials': credentials})
