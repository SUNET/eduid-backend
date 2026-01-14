import logging
import os
from enum import Enum
from http import HTTPStatus
from unittest.mock import patch
from urllib.parse import unquote

from saml2 import BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.mdstore import locations
from saml2.response import AuthnResponse, LogoutResponse
from saml2.typing import SAMLBinding
from werkzeug.test import TestResponse

from eduid.common.testing_base import normalised_data
from eduid.vccs.client import VCCSClient
from eduid.webapp.idp.helpers import IdPAction
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tests.test_api import IdPAPITests

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class LogoutState(Enum):
    S0_REQUEST_FAILED = "request-failed"
    S1_LOGGED_OUT = "logged_out"


class IdPTestLogoutAPI(IdPAPITests):
    def test_basic_logout(self) -> None:
        """This logs in, then out - but it calls the SOAP binding with the SSO cookie present"""

        # pre-accept ToU for this test
        self.add_test_user_tou()

        with self.browser.session_transaction():
            # Patch the VCCSClient so we do not need a vccs server
            with patch.object(VCCSClient, "authenticate"):
                VCCSClient.authenticate.return_value = True  # type: ignore[attr-defined]
                login_result = self._try_login()
                assert login_result.visit_order == [IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED]

            assert login_result.finished_result

            authn_response = self.parse_saml_authn_response(login_result.finished_result)

            reached_state, response = self._try_logout(authn_response, BINDING_SOAP)
            assert reached_state == LogoutState.S1_LOGGED_OUT

            logout_response = self.parse_saml_logout_response(response, BINDING_SOAP)
            assert logout_response.response.status.status_code.value == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def test_basic_logout_soap(self) -> None:
        """
        Simulate a user logging in using one browser,
        and then an SP logging the user out using SOAP with no SSO cookie.
        """

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate"):
            VCCSClient.authenticate.return_value = True  # type: ignore[attr-defined]
            login_result = self._try_login()
            assert login_result.visit_order == [IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED]

        assert login_result.finished_result
        assert login_result.sso_cookie_val

        authn_response = self.parse_saml_authn_response(login_result.finished_result)

        # Locate the SSO session
        sso_session1 = self.app.sso_sessions.get_session(login_result.sso_cookie_val)
        assert isinstance(sso_session1, SSOSession)
        assert sso_session1.eppn == self.test_user.eppn

        # Make sure it is the only SSO session for this user
        user_sso_sessions = self.app.sso_sessions.get_sessions_for_user(self.test_user.eppn)
        assert normalised_data(user_sso_sessions) == normalised_data([sso_session1])

        # Remove all cookies, simulating a SOAP request from an SP rather than from the clients browser
        assert self.browser._cookies
        self.browser._cookies.clear()

        reached_state, response = self._try_logout(authn_response, BINDING_SOAP)
        assert reached_state == LogoutState.S1_LOGGED_OUT

        logout_response = self.parse_saml_logout_response(response, BINDING_SOAP)
        assert logout_response.response.status.status_code.value == "urn:oasis:names:tc:SAML:2.0:status:Success"

        # Make sure the logout removed the SSO session from the database
        sso_session2 = self.app.sso_sessions.get_session(login_result.sso_cookie_val)
        assert sso_session2 is None
        assert self.app.sso_sessions.get_sessions_for_user(self.test_user.eppn) == []

    def test_basic_logout_redirect(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        with self.browser.session_transaction():
            # Patch the VCCSClient so we do not need a vccs server
            with patch.object(VCCSClient, "authenticate"):
                VCCSClient.authenticate.return_value = True  # type: ignore[attr-defined]
                login_result = self._try_login()
                assert login_result.visit_order == [IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED]

            assert login_result.finished_result
            authn_response = self.parse_saml_authn_response(login_result.finished_result)

            reached_state, response = self._try_logout(authn_response, BINDING_HTTP_REDIRECT)
            assert reached_state == LogoutState.S1_LOGGED_OUT

            logout_response = self.parse_saml_logout_response(response, BINDING_HTTP_REDIRECT)
            assert logout_response.response.status.status_code.value == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def parse_saml_logout_response(self, response: TestResponse, binding: SAMLBinding) -> LogoutResponse:
        if binding == BINDING_SOAP:
            xmlstr = response.data
        elif binding == BINDING_HTTP_REDIRECT:
            path = self._extract_path_from_response(response)
            _start = path.index("SAMLResponse=")
            _end = path.index("&RelayState=")
            saml_response = unquote(path[_start + len("SAMLResponse=") : _end])
            xmlstr = saml_response
        else:
            raise RuntimeError(f"Unknown binding {binding}")
        res = self.saml2_client.parse_logout_request_response(xmlstr, binding)
        assert res
        return res

    def _try_logout(self, authn_response: AuthnResponse, binding: SAMLBinding) -> tuple[LogoutState, TestResponse]:
        """
        Try logging out using the IdP.

        :return: Information about how far we got (reached LogoutState) and the last response instance.
        """
        session_info = authn_response.session_info()
        name_id = session_info["name_id"]

        srvs = self.saml2_client.metadata.single_logout_service(self.idp_entity_id, binding, "idpsso")
        _locations = locations(srvs)
        destination = next(_locations)
        session_indexes = [session_info["session_index"]]

        req_id, request = self.saml2_client.create_logout_request(
            destination,
            self.idp_entity_id,
            name_id=name_id,
            reason="",
            expire=None,
            session_indexes=session_indexes,
        )

        relay_state = "testing-testing"
        http_info = self.saml2_client.apply_binding(binding, request, destination, relay_state, sign=False)

        path = self._extract_path_from_url(http_info["url"])
        headers = {}
        # convert list of tuples (name, value) into dict
        for hdr in http_info["headers"]:
            k, v = hdr
            headers[k] = v

        if http_info["method"] == "POST":
            resp = self.browser.post(path, headers=headers, data=http_info["data"])
            if resp.status_code != HTTPStatus.OK:
                return LogoutState.S0_REQUEST_FAILED, resp
        elif http_info["method"] == "GET":
            path = self._extract_path_from_info(http_info)
            resp = self.browser.get(path)
            if resp.status_code != HTTPStatus.FOUND:
                return LogoutState.S0_REQUEST_FAILED, resp
        else:
            raise RuntimeError("Unknown HTTP method")

        return LogoutState.S1_LOGGED_OUT, resp
