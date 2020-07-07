#
# Copyright (c) 2020 SUNET
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
import base64
import json
import pprint
import warnings
from typing import Optional

from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestedCredentialData, AuthenticatorData
from fido2.server import Fido2Server, RelyingParty, U2FFido2Server
from fido2.utils import websafe_decode
from flask import current_app
from u2flib_server.u2f import begin_authentication, complete_authentication

from eduid_userdb.credentials import U2F, Webauthn
from eduid_userdb.user import User

from eduid_common.session import session

RESULT_CREDENTIAL_KEY_NAME = 'cred_key'


class VerificationProblem(Exception):
    def __init__(self, msg: str):
        self.msg = msg


def _get_user_credentials_u2f(user: User) -> dict:
    """
    Get the U2F credentials for the user
    """
    res = {}
    for this in user.credentials.filter(U2F).to_list():
        acd = AttestedCredentialData.from_ctap1(websafe_decode(this.keyhandle), websafe_decode(this.public_key))
        res[this.key] = {
            'u2f': {'version': this.version, 'keyHandle': this.keyhandle, 'publicKey': this.public_key,},
            'webauthn': acd,
            'app_id': this.app_id,
        }
    return res


def _get_user_credentials_webauthn(user: User) -> dict:
    """
    Get the Webauthn credentials for the user
    """
    res = {}
    for this in user.credentials.filter(Webauthn).to_list():
        keyhandle = this.keyhandle
        cred_data = base64.urlsafe_b64decode(this.credential_data.encode('ascii'))
        credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
        version = 'webauthn'
        res[this.key] = {
            'u2f': {'version': version, 'keyHandle': keyhandle, 'publicKey': credential_data.public_key,},
            'webauthn': credential_data,
            'app_id': '',
        }
    return res


def get_user_credentials(user: User) -> dict:
    """
    Get U2F and Webauthn credentials for the user
    """
    res = _get_user_credentials_u2f(user)
    res.update(_get_user_credentials_webauthn(user))
    return res


def _get_fido2server(credentials: dict, fido2rp: RelyingParty) -> Fido2Server:
    # See if any of the credentials is a legacy U2F credential with an app-id
    # (assume all app-ids are the same - authenticating with a mix of different
    # app-ids isn't supported in current Webauthn)
    app_id = None
    for k, v in credentials.items():
        if v['app_id']:
            app_id = v['app_id']
            break
    if app_id:
        return U2FFido2Server(app_id, fido2rp)
    return Fido2Server(fido2rp)


def start_token_verification(user: User, session_prefix: str) -> dict:
    """
    Begin authentication process based on the hardware tokens registered by the user.
    """
    # TODO: Only make Webauthn challenges for Webauthn tokens, and only U2F challenges for U2F tokens?
    credential_data = get_user_credentials(user)
    current_app.logger.debug(f'Extra debug: U2F credentials for user: {user.credentials.filter(U2F).to_list()}')
    current_app.logger.debug(
        f'Extra debug: Webauthn credentials for user: {user.credentials.filter(Webauthn).to_list()}'
    )
    current_app.logger.debug(f'Webauthn credentials for user {user}:\n{pprint.pformat(credential_data)}')

    webauthn_credentials = [v['webauthn'] for v in credential_data.values()]
    fido2rp = RelyingParty(current_app.config.fido2_rp_id, 'eduid.se')  # type: ignore
    fido2server = _get_fido2server(credential_data, fido2rp)
    raw_fido2data, fido2state = fido2server.authenticate_begin(webauthn_credentials)
    current_app.logger.debug(f'FIDO2 authentication data:\n{pprint.pformat(raw_fido2data)}')
    fido2data = base64.urlsafe_b64encode(cbor.encode(raw_fido2data)).decode('ascii')
    fido2data = fido2data.rstrip('=')

    current_app.logger.debug(f'FIDO2/Webauthn state for user {user}: {fido2state}')
    session[session_prefix + '.webauthn.state'] = json.dumps(fido2state)

    return {'webauthn_options': fido2data}


def verify_u2f(user: User, challenge: bytes, token_response: str) -> Optional[dict]:
    """
    verify received U2F data against the user's credentials

    NOTE: We've removed the code to generate U2F challenges from start_token_verification() above,
          so I think that means we will never get such a response back from the client browser
          and it should be possible to remove this code. Right?
    """
    warnings.warn('verify_u2f should be unused, is it not?', DeprecationWarning)
    device, counter, touch = complete_authentication(
        challenge, token_response, current_app.config.u2f_valid_facets  # type: ignore
    )
    current_app.logger.debug(
        'U2F authentication data: {}'.format({'keyHandle': device['keyHandle'], 'touch': touch, 'counter': counter,})
    )

    for this in user.credentials.filter(U2F).to_list():
        if this.keyhandle == device['keyHandle']:
            current_app.logger.info(f'User {user} logged in using U2F token {this} (touch: {touch}, counter {counter})')
            return {
                'success': True,
                'touch': touch,
                'counter': counter,
                RESULT_CREDENTIAL_KEY_NAME: this.key,
            }
    return None


def verify_webauthn(user, request_dict: dict, session_prefix: str) -> dict:
    """
    verify received Webauthn data against the user's credentials
    """
    req = {}
    for this in ['credentialId', 'clientDataJSON', 'authenticatorData', 'signature']:
        try:
            request_dict[this] += '=' * (len(request_dict[this]) % 4)
            req[this] = base64.urlsafe_b64decode(request_dict[this])
        except Exception as exc:
            current_app.logger.error(
                f'Failed to find/b64decode Webauthn '
                f'parameter {this}: {request_dict.get(this)}'
                f'and the exception is {exc}'
            )
            raise VerificationProblem('mfa.bad-token-response')  # XXX add bad-token-response to frontend

    current_app.logger.debug(f'Webauthn request after decoding:\n{pprint.pformat(req)}')
    client_data = ClientData(req['clientDataJSON'])
    auth_data = AuthenticatorData(req['authenticatorData'])

    credentials = get_user_credentials(user)
    fido2state = json.loads(session[session_prefix + '.webauthn.state'])

    rp_id = current_app.config.fido2_rp_id  # type: ignore
    fido2rp = RelyingParty(rp_id, 'eduID')
    fido2server = _get_fido2server(credentials, fido2rp)
    matching_credentials = [
        (v['webauthn'], k) for k, v in credentials.items() if v['webauthn'].credential_id == req['credentialId']
    ]

    if not matching_credentials:
        current_app.logger.error(f"Could not find webauthn credential {req['credentialId']!r} on user {user}")
        raise VerificationProblem('mfa.unknown-token')

    try:
        authn_cred = fido2server.authenticate_complete(
            fido2state,
            [mc[0] for mc in matching_credentials],
            req['credentialId'],
            client_data,
            auth_data,
            req['signature'],
        )
    except Exception:
        raise VerificationProblem('mfa.failed-verification')

    current_app.logger.debug('Authenticated Webauthn credential: {}'.format(authn_cred))

    cred_key = [mc[1] for mc in matching_credentials][0]

    touch = auth_data.flags
    counter = auth_data.counter
    current_app.logger.info(
        f'User {user} logged in using Webauthn token {cred_key} (touch: {touch}, counter {counter})'
    )
    return {
        'success': True,
        'touch': auth_data.is_user_present() or auth_data.is_user_verified(),
        'user_present': auth_data.is_user_present(),
        'user_verified': auth_data.is_user_verified(),
        'counter': counter,
        RESULT_CREDENTIAL_KEY_NAME: cred_key,
    }
