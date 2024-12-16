import json
from typing import Annotated

from fastapi import APIRouter, Form, Request
from pydantic.main import BaseModel

from eduid.vccs.server.config import VCCSConfig
from eduid.vccs.server.db import CredType, RevokedCredential, Status
from eduid.vccs.server.factors import RevokeFactor
from eduid.vccs.server.log import audit_log

revoke_creds_router = APIRouter()


class RevokeCredsRequestV1(BaseModel):
    factors: list[RevokeFactor]
    user_id: str
    version: int


class RevokeCredsResponseV1(BaseModel):
    success: bool
    version: int


class RevokeCredsFormResponse(BaseModel):
    """Extra wrapping class to handle legacy requests sent as form data"""

    revoke_creds_response: RevokeCredsResponseV1


@revoke_creds_router.post("/revoke_creds")
async def revoke_creds_legacy(req: Request, request: Annotated[str, Form(...)]) -> RevokeCredsFormResponse:
    req.app.logger.debug(f"Revoke credentials (using form): {request}")

    class RevokeCredsInnerRequest(BaseModel):
        """Requests all the way down."""

        revoke_creds: RevokeCredsRequestV1

    data = json.loads(request)
    inner = RevokeCredsInnerRequest(**data)

    req.app.logger.debug(f"Inner request: {repr(inner)}")
    inner_response = await revoke_creds(req, inner.revoke_creds)
    response = RevokeCredsFormResponse(revoke_creds_response=inner_response)
    req.app.logger.debug(f"Revoke creds (form) response: {repr(response)}")
    return response


@revoke_creds_router.post("/v2/revoke_creds", response_model=RevokeCredsFormResponse)
async def revoke_creds(req: Request, request: RevokeCredsRequestV1) -> RevokeCredsResponseV1:
    # convenience and typing
    _config = req.app.state.config
    assert isinstance(_config, VCCSConfig)

    results: list[bool] = []
    for factor in request.factors:
        this_result = False
        cred = req.app.state.credstore.get_credential(factor.credential_id)
        if cred:
            if cred.type == CredType.REVOKED:
                req.app.logger.warning(f"Credential already revoked: {factor.credential_id}")
                # Revoking a revoked credential is a NO-OP, not an error
                continue
            revoked_cred = RevokedCredential(
                obj_id=cred.obj_id,
                revision=cred.revision,
                credential_id=cred.credential_id,
                reason=factor.reason,
                reference=factor.reference,
                type=CredType.REVOKED,
                status=Status.DISABLED,
            )
            # Overwrite the previous credential with this object
            res = req.app.state.credstore.save(revoked_cred)
            audit_log(
                f"operation=revoke, reason={repr(factor.reason)}, reference={repr(factor.reference)}, "
                f"credential_id={cred.credential_id}, result={res}"
            )
            if res:
                this_result = True
        else:
            req.app.logger.warning(f"Credential not found: {factor.credential_id}")

        results += [this_result]

    response = RevokeCredsResponseV1(version=1, success=all(results))

    req.app.logger.debug(f"Revoke creds response: {repr(response)}")
    return response
