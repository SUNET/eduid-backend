#
# Copyright (c) 2013, 2014 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Common code for SSO login/logout requests.
"""
from abc import ABC
from html import escape
from typing import Optional

from flask import request
from pydantic import BaseModel, validator
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.session.namespaces import ReqSHA1
from eduid.webapp.idp import mischttp
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.sso_session import SSOSession


class SAMLQueryParams(BaseModel):
    SAMLRequest: Optional[str]
    RelayState: Optional[str]
    key: Optional[ReqSHA1]

    @validator('SAMLRequest', 'RelayState')
    def validate_query_params(cls, v):
        if not isinstance(v, str) or not v:
            ValueError('must be a non-empty string')
        # TODO: perform extra sanitation?
        # return escape(v, quote=True)
        return v

    @validator('key')
    def validate_key(cls, v):
        if v is not None and not isinstance(v, str):
            ValueError('must be a string or None')
        # TODO: perform extra sanitation?
        return escape(v, quote=True)


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
        if request.method == 'GET':
            _data = self.unpack_redirect()
        elif request.method == 'POST':
            _data = self.unpack_post()
        else:
            _data = SAMLQueryParams()
        current_app.logger.debug(f"Unpacked {request.method}, _data: {_data}")
        return _data

    def redirect(self) -> WerkzeugResponse:
        """ Expects a HTTP-redirect request """
        raise NotImplementedError('Subclass should implement function "redirect"')

    def post(self) -> WerkzeugResponse:
        """ Expects a HTTP-POST request """
        raise NotImplementedError('Subclass should implement function "post"')
