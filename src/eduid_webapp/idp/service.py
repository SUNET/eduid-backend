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
from typing import Any, Dict, Optional

from flask import request

from eduid_common.session.sso_session import SSOSession

from eduid_webapp.idp import mischttp
from eduid_webapp.idp.context import IdPContext


class Service(object):
    """
    Base service class. Common code for SSO and SLO classes.

    :param session: SSO session
    :param start_response: WSGI-like start_response function pointer
    :param context: IdP context
    """

    def __init__(self, sso_session: SSOSession, context: IdPContext):
        self.context = context
        self.sso_session = sso_session
        # TODO: Get rid of this copying of things in the context
        self.logger = context.logger
        self.config = context.config

    def unpack_redirect(self) -> Dict[str, str]:
        """
        Unpack redirect (GET) parameters.

        :return: query parameters as dict
        :rtype: dict
        """
        return mischttp.parse_query_string()

    def unpack_post(self) -> Dict[str, Any]:
        """
        Unpack POSTed parameters.

        :return: query parameters as dict
        :rtype: dict
        """
        info = mischttp.get_post(self.logger)
        self.logger.debug(f"unpack_post:: {info}")
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
        self.logger.debug(f"Unpacked {request.method!r}, _dict: {_dict!s}")
        return _dict

    def redirect(self):
        """ Expects a HTTP-redirect request """
        raise NotImplementedError('Subclass should implement function "redirect"')

    def post(self):
        """ Expects a HTTP-POST request """
        raise NotImplementedError('Subclass should implement function "post"')
