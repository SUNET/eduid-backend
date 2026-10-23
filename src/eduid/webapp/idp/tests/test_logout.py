import json
import logging
import os
from enum import Enum
from http import HTTPStatus
from urllib.parse import unquote

from pytest_mock import MockerFixture
from saml2 import BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.mdstore import locations
from saml2.response import AuthnResponse, LogoutResponse
from saml2.typing import SAMLBinding
from werkzeug.test import TestResponse

from eduid.common.testing_base import normalised_data
from eduid.vccs.client import VCCSClient
from eduid.webapp.common.session.eduid_session import EduidSession, SessionFactory
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.namespaces import RequestRef
from eduid.webapp.common.session.redis_session import RedisEncryptedSession, SessionOutOfSync
from eduid.webapp.common.session.testing import force_session_conflict_on_post
from eduid.webapp.idp.helpers import IdPAction
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tests.test_api import IdPAPITests

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class LogoutState(Enum):
    S0_REQUEST_FAILED = "request-failed"
    S1_LOGGED_OUT = "logged_out"


class TestIdPLogoutAPI(IdPAPITests):
    def test_basic_logout(self, mocker: MockerFixture) -> None:
        """This logs in, then out - but it calls the SOAP binding with the SSO cookie present"""

        # pre-accept ToU for this test
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

        with self.browser.session_transaction():
            login_result = self._try_login()
            assert login_result.visit_order == [IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED]

            assert login_result.finished_result

            authn_response = self.parse_saml_authn_response(login_result.finished_result)

            reached_state, response = self._try_logout(authn_response, BINDING_SOAP)
            assert reached_state == LogoutState.S1_LOGGED_OUT

            logout_response = self.parse_saml_logout_response(response, BINDING_SOAP)
            assert logout_response.response.status.status_code.value == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def test_logout_completing_before_next_commits_fails_the_request(self, mocker: MockerFixture) -> None:
        """A /next in flight must not send a SAML response if the session was cleared by a logout meanwhile"""
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

        device = self.browser
        _ref_result = self._get_login_ref(device, self.saml2_client, None, False, None)
        assert isinstance(_ref_result, tuple)
        ref, _ = _ref_result
        _next = self._call_next(device, ref)
        assert _next.payload["action"] == IdPAction.USERNAMEPWAUTH.value
        assert self.default_user.password is not None
        self._call_pwauth(
            device=device,
            target=_next.payload["target"],
            ref=ref,
            username=self.default_user.eppn,
            password=self.default_user.password,
        )

        # The logout (clearing the redis session) completes right before /next commits its session
        with force_session_conflict_on_post(mocker, sibling_action=lambda s: s.clear()) as forcer:
            try:
                result = self._call_next(device, ref)
            except SessionOutOfSync:
                pass  # propagated by the test client
            else:
                assert result.error is not None
                assert "SAMLResponse" not in str(result.payload)
        assert forcer.forced

    def _start_sso_login_in_clean_session(
        self, mocker: MockerFixture, logged_in_eppn: str | None = None
    ) -> tuple[str, str, str]:
        """
        Log in once (creating an SSO session), then start a second login in a fresh browser session that only
        holds the pending request, so that an SSO-completed /next changes nothing but used/idp.ts.

        :param logged_in_eppn: if given, the fresh session is also marked as logged in as this user

        :returns: (login ref, SSO cookie value, session cookie value)
        """
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        first = self._try_login()
        assert first.finished_result is not None
        assert first.sso_cookie_val is not None

        with self.browser.session_transaction() as sess:
            sess.reset()  # as left by /logout: only the CSRF token is retained

        _ref_result = self._get_login_ref(self.browser, self.saml2_client, None, False, None)
        assert isinstance(_ref_result, tuple)
        ref, _ = _ref_result
        with self.browser.session_transaction() as sess:
            if logged_in_eppn is not None:
                sess.common.eppn = logged_in_eppn
                sess.common.is_logged_in = True
            session_cookie_val = sess.meta.cookie_val
        return ref, str(first.sso_cookie_val), session_cookie_val

    def _post_logout_with_ref(self, ref: str, sso_cookie_val: str, session_cookie_val: str) -> TestResponse:
        """POST /logout the way the frontend does, retaining the pending request (idp/views/misc.py:logout)"""
        other = self.app.test_client()
        other.set_cookie(domain=self.test_domain, key=self.app.conf.flask.session_cookie_name, value=session_cookie_val)
        other.set_cookie(domain=self.test_domain, key=self.app.conf.sso_cookie.key, value=sso_cookie_val)
        with other.session_transaction() as sess:
            assert isinstance(sess, EduidSession)
            csrf_token = sess.get_csrf_token()
        response = other.post(
            "/logout", data=json.dumps({"ref": ref, "csrf_token": csrf_token}), content_type=self.content_type_json
        )
        assert response.status_code == HTTPStatus.OK
        assert response.json is not None
        assert response.json["payload"]["finished"] is True
        return response

    def test_retained_request_logout_changing_only_idp_ts_fails_inflight_next(self, mocker: MockerFixture) -> None:
        """
        /logout retains the CSRF token and rebuilds the pending request, and with an SSO-only (managed account)
        session nothing else is in the session. The reset then changes only idp.ts, which the removed-path
        heuristics cannot see, but the session generation does.
        """
        ref, sso_cookie_val, session_cookie_val = self._start_sso_login_in_clean_session(mocker)
        # An SSO-completed /next on a session without common also writes common.eppn/is_logged_in, which would
        # make the conflict fatal on its own. Allow those so that the in-flight request is the one described in
        # the finding: it writes only paths the allowlist considers harmless to lose.
        self.app.conf.session_safe_to_lose_paths = [
            *self.app.conf.session_safe_to_lose_paths,
            "common.eppn",
            "common.is_logged_in",
        ]
        count_spy = mocker.spy(self.app.stats, "count")

        def logout(_sibling: RedisEncryptedSession) -> None:
            self._post_logout_with_ref(ref, sso_cookie_val, session_cookie_val)

        with force_session_conflict_on_post(mocker, sibling_action=logout) as forcer:
            try:
                result = self._call_next(self.browser, ref)
            except SessionOutOfSync:
                pass  # propagated by the test client
            else:
                assert result.error is not None
                assert "SAMLResponse" not in str(result.payload)
        assert forcer.forced
        assert count_spy.call_args_list.count(mocker.call("session_out_of_sync_error")) == 1
        assert mocker.call("session_state_lost") not in count_spy.call_args_list

    def test_logout_then_other_user_login_fails_inflight_next(self, mocker: MockerFixture) -> None:
        """
        Account replacement: after the /logout another user logs in to the same browser session, which restores
        the very same key paths and only changes common.eppn. The in-flight /next of the first user must not
        return that user's assertion.
        """
        ref, sso_cookie_val, session_cookie_val = self._start_sso_login_in_clean_session(
            mocker, logged_in_eppn=self.default_user.eppn
        )
        count_spy = mocker.spy(self.app.stats, "count")
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)

        def logout_then_other_user_logs_in(sibling: RedisEncryptedSession) -> None:
            common = dict(sibling.to_dict()["common"])
            assert common["eppn"] == self.default_user.eppn
            self._post_logout_with_ref(ref, sso_cookie_val, session_cookie_val)
            meta = SessionMeta.from_cookie(session_cookie_val, app_secret=factory.manager.secret)
            other_user_session = factory.manager.get_session(meta=meta, new=False)
            assert "eppn" not in other_user_session.to_dict().get("common", {})  # the logout reset the session
            other_user_session["common"] = {**common, "eppn": "other-eppn"}
            other_user_session.commit()

        with force_session_conflict_on_post(mocker, sibling_action=logout_then_other_user_logs_in) as forcer:
            try:
                result = self._call_next(self.browser, ref)
            except SessionOutOfSync:
                pass  # propagated by the test client
            else:
                assert result.error is not None
                assert "SAMLResponse" not in str(result.payload)
        assert forcer.forced
        assert count_spy.call_args_list.count(mocker.call("session_out_of_sync_error")) == 1
        assert mocker.call("session_state_lost") not in count_spy.call_args_list

    def test_abort_completing_before_next_fails_the_request(self, mocker: MockerFixture) -> None:
        """A /next in flight must not send a SAML response if /abort was committed meanwhile"""
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

        device = self.browser
        _ref_result = self._get_login_ref(device, self.saml2_client, None, False, None)
        assert isinstance(_ref_result, tuple)
        ref, _ = _ref_result
        _next = self._call_next(device, ref)
        assert _next.payload["action"] == IdPAction.USERNAMEPWAUTH.value
        assert self.default_user.password is not None
        self._call_pwauth(
            device=device,
            target=_next.payload["target"],
            ref=ref,
            username=self.default_user.eppn,
            password=self.default_user.password,
        )

        # Finish the request once so common.eppn is in the session, then rearm it, so that the in-flight
        # /next below only changes the allowlisted paths (pending request 'used' and idp.ts)
        first = self._call_next(device, ref)
        assert first.error is None
        assert "SAMLResponse" in str(first.payload)
        with device.session_transaction() as sess:
            sess.idp.pending_requests[RequestRef(ref)].used = False

        def abort(sibling: RedisEncryptedSession) -> None:
            data = sibling.to_dict()
            idp = dict(data["idp"])
            pending = {k: dict(v) for k, v in idp["pending_requests"].items()}
            assert ref in pending
            pending[ref]["aborted"] = True
            idp["pending_requests"] = pending
            sibling["idp"] = idp
            sibling.commit()

        with force_session_conflict_on_post(mocker, sibling_action=abort) as forcer:
            try:
                result = self._call_next(device, ref)
            except SessionOutOfSync:
                pass  # propagated by the test client
            else:
                assert result.error is not None
                assert "SAMLResponse" not in str(result.payload)
        assert forcer.forced

    def test_logout_completing_before_repeated_next_fails_the_request(self, mocker: MockerFixture) -> None:
        """A repeated /next (pending request already used) writes nothing, but must still detect a logout"""
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

        device = self.browser
        _ref_result = self._get_login_ref(device, self.saml2_client, None, False, None)
        assert isinstance(_ref_result, tuple)
        ref, _ = _ref_result
        _next = self._call_next(device, ref)
        assert _next.payload["action"] == IdPAction.USERNAMEPWAUTH.value
        assert self.default_user.password is not None
        self._call_pwauth(
            device=device,
            target=_next.payload["target"],
            ref=ref,
            username=self.default_user.eppn,
            password=self.default_user.password,
        )
        # First /next finishes the request and marks it used
        first = self._call_next(device, ref)
        assert first.error is None
        assert "SAMLResponse" in str(first.payload)

        # The repeat changes nothing in the session, and the logout clears it before the response is returned
        with force_session_conflict_on_post(mocker, sibling_action=lambda s: s.clear()) as forcer:
            try:
                result = self._call_next(device, ref)
            except SessionOutOfSync:
                pass  # propagated by the test client
            else:
                assert result.error is not None
                assert "SAMLResponse" not in str(result.payload)
        assert forcer.forced

    def test_basic_logout_soap(self, mocker: MockerFixture) -> None:
        """
        Simulate a user logging in using one browser,
        and then an SP logging the user out using SOAP with no SSO cookie.
        """

        # pre-accept ToU for this test
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

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

    def test_basic_logout_redirect(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

        with self.browser.session_transaction():
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

        _req_id, request = self.saml2_client.create_logout_request(
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
