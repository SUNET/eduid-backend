# This SAML IdP implementation is derived from the pysaml2 example 'idp2'.
# That code is covered by the following copyright (from pysaml2 LICENSE.txt 2013-05-06) :
#
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY ROLAND HEDBERG ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ROLAND HEDBERG OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# -------------------------------------------------------------------------------
#
# All the changes made during the eduID development are subject to the following
# copyright:
#
# Copyright (c) 2013 SUNET. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SUNET "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL SUNET OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of SUNET.

"""
Common code for SSO login/logout requests.
"""

from abc import ABC
from typing import Any

from flask import request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.session.namespaces import RequestRef
from eduid.webapp.idp import mischttp
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.sso_session import SSOSession


class SAMLQueryParams(BaseModel):
    SAMLRequest: str | None = None
    RelayState: str | None = None
    request_ref: RequestRef | None = Field(default=None, alias="ref")
    model_config = ConfigDict(populate_by_name=True)

    @field_validator("SAMLRequest", "RelayState")
    @classmethod
    def validate_query_params(cls, v: Any):
        if not isinstance(v, str) or not v:
            raise ValueError("must be a non-empty string")
        # TODO: perform extra sanitation?
        return v

    @field_validator("request_ref")
    @classmethod
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

    def __init__(self, sso_session: SSOSession | None) -> None:
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
