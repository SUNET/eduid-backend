"""
Common code for SSO login/logout requests.
"""
from abc import ABC
from typing import Any, Optional

from flask import request
from pydantic import BaseModel, Field, validator
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.session.namespaces import RequestRef
from eduid.webapp.idp import mischttp
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.sso_session import SSOSession


class SAMLQueryParams(BaseModel):
    SAMLRequest: Optional[str]
    RelayState: Optional[str]
    request_ref: Optional[RequestRef] = Field(default=None, alias="ref")

    class Config:
        # Allow setting request_ref using it's name too - not just the alias (ref)
        allow_population_by_field_name = True

    @validator("SAMLRequest", "RelayState")
    def validate_query_params(cls, v: Any):
        if not isinstance(v, str) or not v:
            raise ValueError("must be a non-empty string")
        # TODO: perform extra sanitation?
        return v

    @validator("request_ref")
    def validate_request_ref(cls, v: Any):
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("must be a string or None")
        # TODO: perform extra sanitation? Could check that this is an UUID...
        return v


class Service(ABC):
    """
    Base service class. Common code for SSO and SLO classes.

    :param session: SSO session
    """

    def __init__(self, sso_session: Optional[SSOSession]):
        self.sso_session = sso_session

    def unpack_redirect(self) -> SAMLQueryParams:
        """
        Unpack redirect (GET) parameters.

        :return: query parameters
        """
        info = mischttp.parse_query_string()
        return SAMLQueryParams(**info)

    def unpack_post(self) -> SAMLQueryParams:
        """
        Unpack POSTed parameters.

        :return: query parameters
        """
        info = mischttp.get_post()
        current_app.logger.debug(f"unpack_post:: {info}")
        return SAMLQueryParams(**info)

    def unpack_either(self) -> SAMLQueryParams:
        """
        Unpack either redirect (GET) or POST parameters.

        :return: query parameters
        """
        if request.method == "GET":
            _data = self.unpack_redirect()
        elif request.method == "POST":
            _data = self.unpack_post()
        else:
            _data = SAMLQueryParams()
        current_app.logger.debug(f"Unpacked {request.method}, _data: {_data}")
        return _data

    def redirect(self) -> WerkzeugResponse:
        """Expects a HTTP-redirect request"""
        raise NotImplementedError('Subclass should implement function "redirect"')

    def post(self) -> WerkzeugResponse:
        """Expects a HTTP-POST request"""
        raise NotImplementedError('Subclass should implement function "post"')
