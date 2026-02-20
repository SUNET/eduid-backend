import json
from typing import Annotated

from fastapi import APIRouter, Form, Request
from pydantic.main import BaseModel

from eduid.vccs.server.config import VCCSConfig
from eduid.vccs.server.db import KDF, CredType, PasswordCredential, Status, Version
from eduid.vccs.server.factors import RequestFactor
from eduid.vccs.server.password import calculate_cred_hash

add_creds_router = APIRouter()


class AddCredsRequestV1(BaseModel):
    factors: list[RequestFactor]
    user_id: str
    version: int


class AddCredsResponseV1(BaseModel):
    success: bool
    version: int


class AddCredsFormResponse(BaseModel):
    """Extra wrapping class to handle legacy requests sent as form data"""

    add_creds_response: AddCredsResponseV1


@add_creds_router.post("/add_creds")
async def add_creds_legacy(req: Request, request: Annotated[str, Form(...)]) -> AddCredsFormResponse:
    req.app.logger.debug(f"Add credentials (using form): {request}")

    class AddCredsInnerRequest(BaseModel):
        """Requests all the way down."""

        add_creds: AddCredsRequestV1

    data = json.loads(request)
    inner = AddCredsInnerRequest(**data)

    req.app.logger.debug(f"Inner request: {inner!r}")
    inner_response = await add_creds(req, inner.add_creds)
    response = AddCredsFormResponse(add_creds_response=inner_response)
    req.app.logger.debug(f"Add creds (form) response: {response!r}")
    return response


@add_creds_router.post("/v2/add_creds", response_model=AddCredsFormResponse)
async def add_creds(req: Request, request: AddCredsRequestV1) -> AddCredsResponseV1:
    # convenience and typing
    _config = req.app.state.config
    assert isinstance(_config, VCCSConfig)
    results = []
    for factor in request.factors:
        this_result = False
        if factor.type == CredType.PASSWORD:
            this_result = await _add_password_credential(_config, factor, req, request)
        else:
            req.app.logger.warning(f"Not adding credential with unknown type: {factor}")
        results += [this_result]

    response = AddCredsResponseV1(version=1, success=all(results))

    req.app.logger.debug(f"Add creds response: {response!r}")
    return response


async def _add_password_credential(
    _config: VCCSConfig, factor: RequestFactor, req: Request, request: AddCredsRequestV1
) -> bool:
    version = Version(factor.version)

    # For NDNv2, require new_hasher to be configured
    key_label: str | None = None
    if version == Version.NDNv2:
        if req.app.state.new_hasher is None or _config.new_hasher is None:
            req.app.logger.error("NDNv2 credential requested but new_hasher is not configured")
            return False
        key_label = _config.new_hasher.add_creds_password_key_label
        if key_label is None:
            req.app.logger.error(
                "NDNv2 credential requested but add_creds_password_key_label not configured on new_hasher"
            )
            return False
        _salt = (await req.app.state.new_hasher.safe_random(_config.add_creds_password_salt_bytes)).hex()
        _key_handle = _config.new_hasher.add_creds_password_key_handle
    else:
        _salt = (await req.app.state.hasher.safe_random(_config.add_creds_password_salt_bytes)).hex()
        _key_handle = _config.hasher.add_creds_password_key_handle

    cred = PasswordCredential(
        credential_id=factor.credential_id,
        derived_key="",
        iterations=_config.add_creds_password_kdf_iterations,
        kdf=KDF.PBKDF2_HMAC_SHA512,
        key_handle=_key_handle,
        key_label=key_label,
        salt=_salt,
        status=Status.ACTIVE,
        type=CredType.PASSWORD,
        version=version,
    )
    cred.derived_key = H2 = await calculate_cred_hash(
        user_id=request.user_id,
        H1=factor.H1,
        cred=cred,
        hasher=req.app.state.hasher,
        kdf=req.app.state.kdf,
        new_hasher=req.app.state.new_hasher,
    )
    _res = req.app.state.credstore.add(cred)
    req.app.logger.info(
        f"AUDIT: Add credential credential_id={cred.credential_id}, version={version.value}, H2[16]={H2[:8]}, res={_res!r}"
    )
    return _res
