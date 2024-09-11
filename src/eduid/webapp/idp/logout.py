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
Code handling Single Log Out requests.
"""

from typing import Sequence

import saml2
from flask import request
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.request import LogoutRequest
from saml2.s_utils import error_status_factory
from saml2.saml import NameID
from saml2.samlp import STATUS_PARTIAL_LOGOUT, STATUS_RESPONDER, STATUS_SUCCESS, STATUS_UNKNOWN_PRINCIPAL
from werkzeug.exceptions import BadRequest, InternalServerError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.idp import mischttp
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.idp_saml import gen_key
from eduid.webapp.idp.mischttp import HttpArgs
from eduid.webapp.idp.service import SAMLQueryParams, Service
from eduid.webapp.idp.sso_session import SSOSession, get_sso_session_id
from eduid.webapp.idp.util import maybe_xml_to_string

# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------


class SLO(Service):
    """
    Single Log Out service.
    """

    def redirect(self) -> WerkzeugResponse:
        """Expects a HTTP-redirect request"""

        _data = self.unpack_redirect()
        return self.perform_logout(_data, BINDING_HTTP_REDIRECT)

    def post(self) -> WerkzeugResponse:
        """Expects a HTTP-POST request"""

        _data = self.unpack_post()
        return self.perform_logout(_data, BINDING_HTTP_POST)

    def soap(self) -> WerkzeugResponse:
        """
        Single log out using HTTP_SOAP binding
        """
        _data = self.unpack_soap()
        return self.perform_logout(_data, BINDING_SOAP)

    def unpack_soap(self) -> SAMLQueryParams:
        """
        Turn a SOAP request into the common format of a dict.

        :return: data with 'SAMLRequest' and 'RelayState' items
        """
        # Need to get the body without sanitation
        data = request.stream.read().decode("utf-8")
        return SAMLQueryParams(SAMLRequest=data, RelayState="foo")

    def perform_logout(self, info: SAMLQueryParams, binding: str) -> WerkzeugResponse:
        """
        Perform logout. Means remove SSO session from IdP list, and a best
        effort to contact all SPs that have received assertions using this
        SSO session and letting them know the user has been logged out.

        :param info: Parsed query/POST parameters, SAMLRequest and possibly RelayState
        :param binding: SAML2 binding as string
        :return: SAML StatusCode
        """
        current_app.logger.debug("--- Single Log Out Service ---")
        if not info or not info.SAMLRequest:
            raise BadRequest("Error parsing request or no request")

        request = info.SAMLRequest
        req_key = gen_key(request)

        try:
            req_info = current_app.IDP.parse_logout_request(request, binding)
            assert isinstance(req_info, saml2.request.LogoutRequest)
            current_app.logger.debug(f"Parsed Logout request ({binding}):\n{req_info.message}")
        except Exception:
            current_app.logger.exception("Failed parsing logout request")
            current_app.logger.debug(f"_perform_logout {binding}:\n{info}")
            raise BadRequest("Failed parsing logout request")

        req_info.binding = binding
        if info.RelayState:
            req_info.relay_state = info.RelayState

        # look for the subject
        subject = req_info.subject_id()
        if subject is not None:
            current_app.logger.debug(f"Logout subject: {subject.text.strip()}")
        # XXX should verify issuer (a.k.a. sender()) somehow perhaps
        current_app.logger.debug(f"Logout request sender: {req_info.sender()}")

        _name_id = req_info.message.name_id
        _session_id = get_sso_session_id()
        _username = None
        sessions: list[SSOSession] = []
        if _session_id:
            # If the binding is REDIRECT, we can get the SSO session to log out from the
            # client using the SSO cookie
            _session = current_app.sso_sessions.get_session(_session_id)
            if _session:
                sessions += [_session]
        else:
            # For SOAP binding, no cookie is sent - only NameID. Have to figure out
            # the user based on NameID and then destroy *all* the users SSO sessions
            # unfortunately.
            _username = current_app.IDP.ident.find_local_id(_name_id)
            current_app.logger.debug(f"Logout message name_id: {repr(_name_id)} found username {repr(_username)}")
            sessions += current_app.sso_sessions.get_sessions_for_user(_username)

        _session_ids = [x.session_id for x in sessions]
        current_app.logger.debug(
            f"Logout resources: name_id {repr(_name_id)} username {repr(_username)}, session_ids {_session_ids}"
        )

        if sessions:
            status_code = self._logout_session_ids(sessions, req_key)
        else:
            # No specific SSO session(s) were found, we have no choice but to logout ALL
            # the sessions for this NameID.
            status_code = self._logout_name_id(_name_id, req_key)

        current_app.logger.debug(f"Logout of sessions {sessions!r} / NameID {_name_id!r} result : {status_code!r}")
        return self._logout_response(req_info, status_code, req_key)

    def _logout_session_ids(self, sessions: Sequence[SSOSession], req_key: str) -> str:
        """
        Terminate one or more specific SSO sessions.

        :param session_ids: List of db keys in SSO session database
        :param req_key: Logging id of request
        :return: SAML StatusCode
        """
        fail = 0
        for this in sessions:
            current_app.logger.debug(f"Logging out SSO session: {repr(this.session_id)}")
            try:
                res = current_app.sso_sessions.remove_session(this)
                current_app.logger.info(
                    f"{req_key}: logout sso_session={repr(this.public_id)}, age={this.age}, result={bool(res)}"
                )
            except KeyError:
                current_app.logger.info(f"{req_key}: logout sso_key={repr(this)}, result=not_found")
                res = False
            if not res:
                fail += 1
        if fail:
            if fail == len(sessions):
                return str(STATUS_RESPONDER)  # use str() to ensure external value is the right type
            return str(STATUS_PARTIAL_LOGOUT)  # use str() to ensure external value is the right type
        return str(STATUS_SUCCESS)  # use str() to ensure external value is the right type

    def _logout_name_id(self, name_id: NameID, req_key: str) -> str:
        """
        Terminate ALL SSO sessions found using this NameID.

        This is not as nice as _logout_session_ids(), as it would log a user
        out of sessions across multiple devices - probably not the expected thing
        to happen from a user perspective when clicking Logout on their phone.

        :param name_id: NameID from LogoutRequest
        :param req_key: Logging id of request
        :return: SAML StatusCode
        """
        if not name_id:
            current_app.logger.debug("No NameID provided for logout")
            return str(STATUS_UNKNOWN_PRINCIPAL)  # use str() to ensure external value is the right type
        try:
            # remove the authentication
            # XXX would be useful if remove_authn_statements() returned how many statements it actually removed
            current_app.IDP.session_db.remove_authn_statements(name_id)
            current_app.logger.info(f"{req_key}: logout name_id={name_id!r}")
        except KeyError:
            current_app.logger.exception("Failed removing authn")
            raise InternalServerError()
        return str(STATUS_SUCCESS)  # use str() to ensure external value is the right type

    def _logout_response(
        self, req_info: LogoutRequest, status_code: str, req_key: str, sign_response: bool = True
    ) -> WerkzeugResponse:
        """
        Create logout response.

        :param req_info: Logout request
        :param status_code: logout result (e.g. 'urn:oasis:names:tc:SAML:2.0:status:Success')
        :param req_key: SAML request id
        :param sign_response: cryptographically sign response or not
        :return: HTML response

        :type req_info: saml2.request.LogoutRequest
        :type status_code: string
        :type req_key: string
        :type sign_response: bool
        :rtype: string
        """
        current_app.logger.debug(
            f"LOGOUT of '{req_info.subject_id()}' by '{req_info.sender()}', success={status_code!r}"
        )
        if req_info.binding != BINDING_SOAP:
            bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
            binding, destination = current_app.IDP.pick_binding(
                "single_logout_service", bindings, entity_id=req_info.sender()
            )
            bindings = [binding]
        else:
            bindings = [BINDING_SOAP]
            destination = ""

        status = None  # None == success in create_logout_response()
        if status_code != saml2.samlp.STATUS_SUCCESS:
            status = error_status_factory((status_code, "Logout failed"))
            current_app.logger.debug(f"Created 'logout failed' status based on {status_code!r} : {status!r}")

        issuer = current_app.IDP._issuer(current_app.IDP.config.entityid)
        response = current_app.IDP.create_logout_response(
            req_info.message, bindings, status, sign=sign_response, issuer=issuer
        )
        # Only perform expensive parse/pretty-print if debugging
        if current_app.conf.debug:
            xmlstr = maybe_xml_to_string(response)
            current_app.logger.debug(f"Logout SAMLResponse :\n\n{xmlstr}\n\n")

        _args = current_app.IDP.apply_binding(
            bindings[0], str(response), destination, req_info.relay_state, response=True
        )
        http_args = HttpArgs.from_pysaml2_dict(_args)

        # INFO-Log the SAML request ID, result of logout and destination
        current_app.logger.info(f"{req_key}: logout status={status_code!r}, dst={destination}")

        # XXX old code checked 'if req_info.binding == BINDING_HTTP_REDIRECT:', but it looks like
        # it would be more correct to look at bindings[0] here, since `bindings' is what was used
        # with create_logout_response() and apply_binding().
        if req_info.binding != bindings[0]:
            current_app.logger.debug(
                f"Creating response with binding {bindings[0]!r} instead of {req_info.binding!r} used before"
            )

        res = mischttp.create_html_response(bindings[0], http_args)

        # Delete the SSO session cookie in the browser
        res.delete_cookie(
            key=current_app.conf.sso_cookie.key,
            path=current_app.conf.sso_cookie.path,
            domain=current_app.conf.sso_cookie.domain,
        )
        return res
