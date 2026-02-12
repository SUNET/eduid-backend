import json
from typing import Annotated

from fastapi import APIRouter, Form, Request
from pydantic.main import BaseModel

from eduid.vccs.server.config import VCCSConfig
from eduid.vccs.server.db import CredType, Status
from eduid.vccs.server.factors import RequestFactor
from eduid.vccs.server.log import audit_log
from eduid.vccs.server.password import authenticate_password

authenticate_router = APIRouter()


class AuthenticateRequestV1(BaseModel):
    factors: list[RequestFactor]
    user_id: str
    version: int


class AuthenticateResponseV1(BaseModel):
    authenticated: bool
    version: int


class AuthenticateFormResponse(BaseModel):
    """Extra wrapping class to handle legacy requests sent as form data"""

    auth_response: AuthenticateResponseV1


@authenticate_router.post("/authenticate")
async def authenticate_legacy(req: Request, request: Annotated[str, Form(...)]) -> AuthenticateFormResponse:
    req.app.logger.debug(f"Authenticate (using form): {request}")

    class AuthenticateInnerRequest(BaseModel):
        """Requests all the way down."""

        auth: AuthenticateRequestV1

    data = json.loads(request)
    inner = AuthenticateInnerRequest(**data)

    req.app.logger.debug(f"Inner request: {inner!r}")
    inner_response = await authenticate(req, inner.auth)
    response = AuthenticateFormResponse(auth_response=inner_response)
    req.app.logger.debug(f"Authenticate (form) response: {response!r}")
    return response


@authenticate_router.post("/v2/authenticate")
async def authenticate(req: Request, request: AuthenticateRequestV1) -> AuthenticateResponseV1:
    """
    Handle a password authentication request, along the following pseudo-code :

    On backend :
    ------------
    T1 = 'A' | user_id | credential_id | H1
    T2 = PBKDF2-HMAC-SHA512(T1, iterations=many, salt)
    local_salt = yhsm_hmac_sha1(T2)
    H2 = PBKDF2-HMAC-SHA512(T2, iterations=1, local_salt)

    audit_log(frontend_id, credential_id, H2, credential_stored_hash)

    return (H2 == credential_stored_hash)

    See the VCCS/README file for a longer reasoning about this scheme.

    :returns: True on successful authentication, False otherwise
    """
    # convenience and typing
    _config = req.app.state.config
    assert isinstance(_config, VCCSConfig)

    results: list[bool] = []
    # TODO: Make sure to respond False if request.factors is empty.
    for factor in request.factors:
        this_result = False
        cred = req.app.state.credstore.get_credential(factor.credential_id)
        if cred:
            if cred.status != Status.ACTIVE:
                audit_log(
                    f"result=FAIL, factor=password, credential_id={cred.credential_id}, status={cred.status.value}"
                )
            elif cred.type == CredType.PASSWORD:
                this_result = await authenticate_password(
                    cred, factor, request.user_id, req.app.state.hasher, req.app.state.kdf
                )
            else:
                req.app.logger.warning(f"Unsupported credential type: {cred!r}")
        else:
            req.app.logger.warning(f"Credential not found: {factor.credential_id}")

        results += [this_result]

    response = AuthenticateResponseV1(version=1, authenticated=all(results))
    req.app.logger.debug(f"Authenticate: {response!r}")
    return response
