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
from typing import Any, Dict

from flask import request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid_webapp.idp import mischttp
from eduid_webapp.idp.app import current_idp_app as current_app
from eduid_webapp.idp.sso_session import SSOSession


class Service(ABC):
    """
    Base service class. Common code for SSO and SLO classes.

    :param session: SSO session
    """

    def __init__(self, sso_session: SSOSession):
        self.sso_session = sso_session

    def unpack_redirect(self) -> Dict[str, str]:
        """
        Unpack redirect (GET) parameters.

        :return: query parameters as dict
        """
        return mischttp.parse_query_string()

    def unpack_post(self) -> Dict[str, Any]:
        """
        Unpack POSTed parameters.

        :return: query parameters as dict
        """
        info = mischttp.get_post()
        current_app.logger.debug(f"unpack_post:: {info}")
        try:
            return dict([(k, v) for k, v in info.items()])
        except AttributeError:
            return {}

    def unpack_either(self) -> Dict[str, str]:
        """
        Unpack either redirect (GET) or POST parameters.

        :return: query parameters as dict
        """
        if request.method == 'GET':
            _dict = self.unpack_redirect()
        elif request.method == 'POST':
            _dict = self.unpack_post()
        else:
            _dict = {}
        current_app.logger.debug(f"Unpacked {request.method!r}, _dict: {_dict!s}")
        return _dict

    def redirect(self) -> WerkzeugResponse:
        """ Expects a HTTP-redirect request """
        raise NotImplementedError('Subclass should implement function "redirect"')

    def post(self) -> WerkzeugResponse:
        """ Expects a HTTP-POST request """
        raise NotImplementedError('Subclass should implement function "post"')
