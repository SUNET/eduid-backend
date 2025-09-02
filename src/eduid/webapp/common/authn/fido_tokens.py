import base64
import json
import logging
import pprint
from typing import Any

from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)
from pydantic import BaseModel

from eduid.common.models.webauthn import WebauthnChallenge
from eduid.userdb.credentials import U2F, Webauthn
from eduid.userdb.element import ElementKey
from eduid.userdb.user import User
from eduid.webapp.common.session.namespaces import MfaAction, WebauthnState

logger = logging.getLogger(__name__)


class VerificationProblem(Exception):
    def __init__(self, msg: str) -> None:
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


def _get_user_credentials_webauthn(user: User, mfa_approved: bool | None = None) -> dict[ElementKey, FidoCred]:
    """
    Get the Webauthn credentials for the user
    """
    res: dict[ElementKey, FidoCred] = {}
    for this in user.credentials.filter(Webauthn):
        if mfa_approved is not None and this.mfa_approved is not mfa_approved:
            continue
        cred_data = base64.urlsafe_b64decode(this.credential_data.encode("ascii"))
        credential_data, _rest = AttestedCredentialData.unpack_from(cred_data)
        version = "webauthn"
        res[this.key] = FidoCred(
            app_id="",
            u2f={"version": version, "keyHandle": this.keyhandle, "publicKey": credential_data.public_key},
            webauthn=credential_data,
        )
    return res


def get_user_credentials(user: User, mfa_approved: bool | None = None) -> dict[ElementKey, FidoCred]:
    """
    Get U2F and Webauthn credentials for the user
    """
    res: dict[ElementKey, FidoCred] = {}
    # If mfa_approved is None or False, get both U2F credentials as they do not support user verification
    if mfa_approved is None or mfa_approved is False:
        res = _get_user_credentials_u2f(user)
    res.update(_get_user_credentials_webauthn(user, mfa_approved=mfa_approved))
    return res


def start_token_verification(
    user: User,
    fido2_rp_id: str,
    fido2_rp_name: str,
    state: MfaAction,
    user_verification: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
    credential_data: dict[ElementKey, FidoCred] | None = None,
) -> WebauthnChallenge:
    """
    Begin authentication process based on the hardware tokens registered by the user.
    """
    if credential_data is None:
        # get all credentials for the user if not provided
        credential_data = get_user_credentials(user)
    logger.debug(f"Extra debug: U2F credentials for user: {[str(x) for x in user.credentials.filter(U2F)]}")
    logger.debug(f"Extra debug: Webauthn credentials for user: {[str(x) for x in user.credentials.filter(Webauthn)]}")
    logger.debug(f"FIDO credentials for user {user}:\n{pprint.pformat(list(credential_data.keys()))}")

    webauthn_credentials = [v.webauthn for v in credential_data.values()]

    fido2rp = PublicKeyCredentialRpEntity(id=fido2_rp_id, name=fido2_rp_name)
    fido2server = Fido2Server(fido2rp)
    fido2state: WebauthnState
    credential_request_options, fido2state = fido2server.authenticate_begin(
        webauthn_credentials, user_verification=user_verification
    )

    logger.debug(f"FIDO2 authentication data:\n{pprint.pformat(dict(credential_request_options))}")

    logger.debug(f"FIDO2/Webauthn state for user {user}: {fido2state}")
    state.webauthn_state = fido2state

    return WebauthnChallenge(webauthn_options=dict(credential_request_options.public_key))


class WebauthnResult(BaseModel):
    success: bool
    touch: bool
    user_present: bool
    user_verified: bool
    counter: int
    credential_key: ElementKey


def verify_webauthn(
    user: User, auth_response: AuthenticationResponse, rp_id: str, rp_name: str, state: MfaAction
) -> WebauthnResult:
    """
    Verify received Webauthn data against the user's credentials.

    The request_dict looks like this:

    {
        "authenticatorAttachment": "cross-platform",
        "clientExtensionResults": {},
        "id": "base64",
        "rawId": "base64",
        "response": {
            "authenticatorData": "base64",
            "clientDataJSON": "base64",
            "signature": "base64"
        },
        "type": "public-key"
    }

    """
    logger.debug(f"Webauthn request:\n{json.dumps(dict(auth_response), indent=4)}")

    credentials = get_user_credentials(user)

    fido2rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    fido2server = Fido2Server(fido2rp)
    # Filter out the FidoCred that has webauthn.credential_id matching the credentialId in the request
    matching_credentials = {k: v for k, v in credentials.items() if v.webauthn.credential_id == auth_response.raw_id}

    if not matching_credentials:
        logger.error(f"Could not find webauthn credential {repr(auth_response.raw_id)} on user {user}")
        raise VerificationProblem("mfa.unknown-token")

    try:
        authn_cred = fido2server.authenticate_complete(
            state=state.webauthn_state,
            credentials=[this.webauthn for this in matching_credentials.values()],
            response=auth_response,
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

    touch = auth_response.response.authenticator_data.flags
    counter = auth_response.response.authenticator_data.counter
    logger.info(f"User {user} logged in using Webauthn token {cred_key} (touch: {touch}, counter {counter})")
    return WebauthnResult(
        success=True,
        touch=auth_response.response.authenticator_data.is_user_present()
        or auth_response.response.authenticator_data.is_user_verified(),
        user_present=auth_response.response.authenticator_data.is_user_present(),
        user_verified=auth_response.response.authenticator_data.is_user_verified(),
        counter=counter,
        credential_key=cred_key,
    )
