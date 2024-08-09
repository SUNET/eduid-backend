import logging
from abc import ABC
from datetime import datetime, timedelta
from typing import Annotated, Any, Coroutine, Optional, Union

from httpx import Request
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.generic import JWKPydanticAnnotation
from eduid.common.models.gnap_models import (
    Access,
    AccessTokenFlags,
    AccessTokenRequest,
    Client,
    GNAPJOSEHeader,
    GrantRequest,
    GrantResponse,
)
from eduid.common.models.jose_models import SupportedAlgorithms, SupportedHTTPMethods, SupportedJWSType
from eduid.common.utils import urlappend

__author__ = "lundberg"

logger = logging.getLogger(__name__)


ClientJWK = Annotated[JWK, JWKPydanticAnnotation]


class GNAPClientException(Exception):
    pass


class GNAPClientAuthData(BaseModel):
    authn_server_url: str
    authn_server_verify: bool = True
    key_name: str
    client_jwk: ClientJWK
    access: list[Union[str, Access]] = Field(default_factory=list)
    default_access_token_expires_in: timedelta = timedelta(hours=1)


class GNAPBearerTokenMixin(ABC):
    _auth_data: GNAPClientAuthData
    _bearer_token: Optional[str] = None
    _bearer_token_expires_at: datetime = utc_now()

    @property
    def transaction_uri(self) -> str:
        return urlappend(self._auth_data.authn_server_url, "transaction")

    def _create_grant_request_jws(self) -> str:
        req = GrantRequest(
            client=Client(key=self._auth_data.key_name),
            access_token=AccessTokenRequest(flags=[AccessTokenFlags.BEARER], access=self._auth_data.access),
        )
        logger.debug(f"grant request: {req}")
        jws_header = GNAPJOSEHeader(
            typ=SupportedJWSType.JWS,
            alg=SupportedAlgorithms.ES256,
            kid=self._auth_data.client_jwk.key_id,
            htm=SupportedHTTPMethods.POST,
            uri=self.transaction_uri,
            created=utc_now(),
        )
        _jws = JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self._auth_data.client_jwk,
            protected=jws_header.json(exclude_none=True),
        )
        return _jws.serialize(compact=True)

    def _set_bearer_token(self, grant_response: GrantResponse) -> None:
        logger.debug(f"gnap response: {grant_response}")
        if grant_response.access_token is None:
            raise GNAPClientException("No access token returned")
        self._bearer_token = grant_response.access_token.value
        expires_in = self._auth_data.default_access_token_expires_in
        if grant_response.access_token.expires_in is not None:
            expires_in = timedelta(seconds=grant_response.access_token.expires_in)
        self._bearer_token_expires_at = utc_now() + expires_in

    def _has_bearer_token(self) -> bool:
        return self._bearer_token is not None and self._bearer_token_expires_at > utc_now()

    def _request_bearer_token(self) -> Union[GrantResponse, Coroutine[Any, Any, GrantResponse]]:
        raise NotImplementedError()

    def _add_authz_header(self, request: Request) -> Union[None, Coroutine[Any, Any, None]]:
        raise NotImplementedError()
