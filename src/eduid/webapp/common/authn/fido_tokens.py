import base64
import json
import logging
import pprint
from collections.abc import Mapping
from typing import Any

from fido2 import cbor
from fido2.server import Fido2Server, U2FFido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData, PublicKeyCredentialRpEntity
from pydantic import BaseModel

from eduid.common.models.webauthn import WebauthnChallenge
from eduid.userdb.credentials import U2F, Webauthn
from eduid.userdb.element import ElementKey
from eduid.userdb.user import User
from eduid.webapp.common.session.namespaces import MfaAction, WebauthnState

logger = logging.getLogger(__name__)


class VerificationProblem(Exception):
    def __init__(self, msg: str):
        self.msg = msg


class FidoCred(BaseModel):
    app_id: str
    u2f: dict[str, Any]  # TODO: This can probably be removed
    # pydantic (1.8.2) bugs out if webauthn is typed as 'AttestedCredentialData' :/
    # (saying Expected bytes, got AttestedCredentialData (type=type_error))
    webauthn: Any = None


def _get_user_credentials_u2f(user: User) -> dict[ElementKey, FidoCred]:
    """
    Get the U2F credentials for the user
    """
    res: dict[ElementKey, FidoCred] = {}
    for this in user.credentials.filter(U2F):
        acd = AttestedCredentialData.from_ctap1(websafe_decode(this.keyhandle), websafe_decode(this.public_key))
        res[this.key] = FidoCred(
            app_id=this.app_id,
            u2f={"version": this.version, "keyHandle": this.keyhandle, "publicKey": this.public_key},
            webauthn=acd,
        )
    return res


def _get_user_credentials_webauthn(user: User) -> dict[ElementKey, FidoCred]:
    """
    Get the Webauthn credentials for the user
    """
    res: dict[ElementKey, FidoCred] = {}
    for this in user.credentials.filter(Webauthn):
        cred_data = base64.urlsafe_b64decode(this.credential_data.encode("ascii"))
        credential_data, _rest = AttestedCredentialData.unpack_from(cred_data)
        version = "webauthn"
        res[this.key] = FidoCred(
            app_id="",
            u2f={"version": version, "keyHandle": this.keyhandle, "publicKey": credential_data.public_key},
            webauthn=credential_data,
        )
    return res


def get_user_credentials(user: User) -> dict[ElementKey, FidoCred]:
    """
    Get U2F and Webauthn credentials for the user
    """
    res = _get_user_credentials_u2f(user)
    res.update(_get_user_credentials_webauthn(user))
    return res


def _get_fido2server(credentials: dict[ElementKey, FidoCred], fido2rp: PublicKeyCredentialRpEntity) -> Fido2Server:
    # See if any of the credentials is a legacy U2F credential with an app-id
    # (assume all app-ids are the same - authenticating with a mix of different
    # app-ids isn't supported in current Webauthn)
    app_id = None
    for _k, v in credentials.items():
        if v.app_id:
            app_id = v.app_id
            break
    if app_id:
        return U2FFido2Server(app_id, fido2rp)
    return Fido2Server(fido2rp)


def start_token_verification(user: User, fido2_rp_id: str, fido2_rp_name: str, state: MfaAction) -> WebauthnChallenge:
    """
    Begin authentication process based on the hardware tokens registered by the user.
    """
    credential_data = get_user_credentials(user)
    logger.debug(f"Extra debug: U2F credentials for user: {[str(x) for x in user.credentials.filter(U2F)]}")
    logger.debug(f"Extra debug: Webauthn credentials for user: {[str(x) for x in user.credentials.filter(Webauthn)]}")
    logger.debug(f"FIDO credentials for user {user}:\n{pprint.pformat(list(credential_data.keys()))}")

    webauthn_credentials = [v.webauthn for v in credential_data.values()]

    fido2rp = PublicKeyCredentialRpEntity(id=fido2_rp_id, name=fido2_rp_name)
    fido2server = _get_fido2server(credential_data, fido2rp)
    fido2state: WebauthnState
    raw_fido2data, fido2state = fido2server.authenticate_begin(webauthn_credentials)

    logger.debug(f"FIDO2 authentication data:\n{pprint.pformat(raw_fido2data)}")
    fido2data = base64.urlsafe_b64encode(cbor.encode(raw_fido2data)).decode("ascii")
    fido2data = fido2data.rstrip("=")

    logger.debug(f"FIDO2/Webauthn state for user {user}: {fido2state}")
    state.webauthn_state = fido2state

    return WebauthnChallenge(webauthn_options=fido2data)


class WebauthnRequest(BaseModel):
    credentialId: bytes
    clientDataJSON: bytes
    authenticatorData: bytes
    signature: bytes


class WebauthnResult(BaseModel):
    success: bool
    touch: bool
    user_present: bool
    user_verified: bool
    counter: int
    credential_key: ElementKey


def verify_webauthn(
    user: User, request_dict: Mapping[str, Any], rp_id: str, rp_name: str, state: MfaAction
) -> WebauthnResult:
    """
    Verify received Webauthn data against the user's credentials.

    The request_dict looks like this:

    {
        "credentialId": base64,
        "authenticatorData": base64,
        "clientDataJSON": base64,
        "signature": base64,
    }

    """
    logger.debug(f"Webauthn request:\n{json.dumps(request_dict, indent=4)}")

    def _decode(key: str) -> bytes:
        try:
            data = request_dict[key]
            data += "=" * (len(data) % 4)
            return base64.urlsafe_b64decode(data)
        except Exception:
            logger.exception(f"Failed to find/b64decode Webauthn parameter {key}: {request_dict.get(key)}")
            raise VerificationProblem("mfa.bad-token-response")  # XXX add bad-token-response to frontend

    req = WebauthnRequest(
        credentialId=_decode("credentialId"),
        clientDataJSON=_decode("clientDataJSON"),
        authenticatorData=_decode("authenticatorData"),
        signature=_decode("signature"),
    )
    client_data = CollectedClientData(req.clientDataJSON)
    auth_data = AuthenticatorData(req.authenticatorData)

    credentials = get_user_credentials(user)

    fido2rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    fido2server = _get_fido2server(credentials, fido2rp)
    # Filter out the FidoCred that has webauthn.credential_id matching the credentialId in the request
    matching_credentials = {k: v for k, v in credentials.items() if v.webauthn.credential_id == req.credentialId}

    if not matching_credentials:
        logger.error(f"Could not find webauthn credential {repr(req.credentialId)} on user {user}")
        raise VerificationProblem("mfa.unknown-token")

    try:
        authn_cred = fido2server.authenticate_complete(
            state.webauthn_state,
            [this.webauthn for this in matching_credentials.values()],
            req.credentialId,
            client_data,
            auth_data,
            req.signature,
        )
    except Exception:
        logger.exception("Webauthn authentication failed")
        raise VerificationProblem("mfa.failed-verification")

    logger.debug(f"Authenticated Webauthn credential: {authn_cred}")

    # Filter out the exact FidoCred that was actually used for the authentication
    authn_credentials = {k: v for k, v in credentials.items() if v.webauthn == authn_cred}

    if len(authn_credentials) != 1:
        logger.error("Unable to find exactly the webauthn credential that was used for authentication")
        logger.debug(f"Matching credentials: {matching_credentials}")
        logger.debug(f"Authn credential: {authn_cred}")
        logger.debug(f"Authn credentials: {authn_credentials}")
        raise RuntimeError("Unable to find exactly the webauthn credential that was used for authentication")

    cred_key = list(authn_credentials.keys())[0]

    touch = auth_data.flags
    counter = auth_data.counter
    logger.info(f"User {user} logged in using Webauthn token {cred_key} (touch: {touch}, counter {counter})")
    return WebauthnResult(
        success=True,
        touch=auth_data.is_user_present() or auth_data.is_user_verified(),
        user_present=auth_data.is_user_present(),
        user_verified=auth_data.is_user_verified(),
        counter=counter,
        credential_key=cred_key,
    )
