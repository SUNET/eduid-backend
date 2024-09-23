import base64
import json
from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock, patch

from flask import Blueprint, current_app, request

from eduid.common.config.base import EduIDBaseAppConfig, WebauthnConfigMixin2
from eduid.common.config.parsers import load_config
from eduid.userdb.fixtures.fido_credentials import u2f_credential, webauthn_credential
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.fido_tokens import VerificationProblem, start_token_verification, verify_webauthn
from eduid.webapp.common.session.namespaces import WebauthnState


class MockFidoConfig(EduIDBaseAppConfig, WebauthnConfigMixin2):
    mfa_testing: bool = True
    generate_u2f_challenges: bool = True


views = Blueprint("testing", "testing", url_prefix="")


@views.route("/start", methods=["GET"])
def start_verification():
    current_app.logger.info("Endpoint start_verification called")
    user = current_app.central_userdb.get_user_by_eppn("hubba-bubba")
    data = json.loads(request.query_string[len("webauthn_request=") :])
    from eduid.webapp.common.session import session

    try:
        result = verify_webauthn(
            user=user,
            request_dict=data,
            rp_id=current_app.conf.fido2_rp_id,
            rp_name=current_app.conf.fido2_rp_name,
            state=session.mfa_action,
        ).json()
    except VerificationProblem as exc:
        current_app.logger.error(f"Webauthn verification failed: {repr(exc)}")
        result = {"success": False, "message": "mfa.verification-problem"}
    current_app.logger.info(f"Endpoint start_verification result: {result}")
    return result


class MockFidoApp(EduIDBaseApp):
    def __init__(self, config: MockFidoConfig):
        super().__init__(config)

        self.conf = config


# These values were extracted from a working webauthn login in our development environment.
#
# The webauthn configuration in the MockFidoApp's config also has to match what was used
# when this request/state was generated, otherwise validation will fail.
#
SAMPLE_WEBAUTHN_REQUEST = {
    "credentialId": "i3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_Q",
    "authenticatorData": "3PcEcSYqagziJNECYxSBKMR01J4pmySHIPPDM-42YdMBAAAGNw",
    # {                                                             # noqa: ERA001
    #   "type":"webauthn.get",                                      # noqa: ERA001
    #   "challenge":"saoY-78kzDgV6mX5R2ixraC699jEU1cJTu7I9twUfJQ",  # noqa: ERA001
    #   "origin":"https://idp.eduid.docker",                        # noqa: ERA001
    #   "crossOrigin":false
    # }                                                             # noqa: ERA001
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoic2FvWS03OGt6RGdWNm1YNVIyaXhyYUM2OTlqRVUxY0pU"
    "dTdJOXR3VWZKUSIsIm9yaWdpbiI6Imh0dHBzOi8vaWRwLmVkdWlkLmRvY2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    # This is a fake signature, we mock its verification below
    "signature": "MEUCICVPIQ5fO6gXtu3nXD9ff5ILcmWc54m6AxvK9vcS8IjkAiEAoFAKblpl29UHK6AhnOf6r7hezTZeQdK5lB4J3F-cguY",
}

SAMPLE_WEBAUTHN_FIDO2STATE = WebauthnState(
    {
        "challenge": "saoY-78kzDgV6mX5R2ixraC699jEU1cJTu7I9twUfJQ",
        "user_verification": "preferred",
    }
)


SAMPLE_WEBAUTHN_APP_CONFIG = {
    "fido2_rp_id": "eduid.docker",
}


class FidoTokensTestCase(EduidAPITestCase):
    app: MockFidoApp

    def setUp(self):
        super().setUp()
        self.webauthn_credential = webauthn_credential
        self.u2f_credential = u2f_credential

    def load_app(self, test_config: Mapping[str, Any]) -> MockFidoApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=MockFidoConfig, app_name="testing", ns="webapp", test_config=test_config)
        app = MockFidoApp(config)
        app.register_blueprint(views)
        return app

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "app_name": "testing",
                "available_languages": {"en": "English", "sv": "Svenska"},
            }
        )
        config.update(SAMPLE_WEBAUTHN_APP_CONFIG)
        return config

    def test_u2f_start_verification(self):
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.u2f_credential)
        self.amdb.save(self.test_user)

        eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    challenge = start_token_verification(
                        user=self.test_user,
                        fido2_rp_id=self.app.conf.fido2_rp_id,
                        fido2_rp_name=self.app.conf.fido2_rp_name,
                        state=sess.mfa_action,
                    )
                    s = challenge.webauthn_options
                    _decoded = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
                    # _decoded is still CBOR encoded, so we just check for some known strings
                    assert b"publicKey" in _decoded
                    assert bytes(self.app.conf.fido2_rp_id, "ascii") in _decoded
                    assert b"challenge" in _decoded
                    assert sess.mfa_action.webauthn_state is not None

    def test_webauthn_start_verification(self):
        # Add a working Webauthn credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user)

        eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    challenge = start_token_verification(
                        user=self.test_user,
                        fido2_rp_id=self.app.conf.fido2_rp_id,
                        fido2_rp_name=self.app.conf.fido2_rp_name,
                        state=sess.mfa_action,
                    )
                    s = challenge.webauthn_options
                    _decoded = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
                    # _decoded is still CBOR encoded, so we just check for some known strings
                    assert b"publicKey" in _decoded
                    assert bytes(self.app.conf.fido2_rp_id, "ascii") in _decoded
                    assert b"challenge" in _decoded
                    assert sess.mfa_action.webauthn_state is not None

    @patch("fido2.cose.ES256.verify")
    def test_webauthn_verify(self, mock_verify: MagicMock):
        mock_verify.return_value = True
        # Add a working webauthn credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user)

        with self.app.test_request_context():
            with self.session_cookie(self.browser, self.test_user.eppn) as client:
                with client.session_transaction() as sess:
                    sess.mfa_action.webauthn_state = SAMPLE_WEBAUTHN_FIDO2STATE
                    sess.persist()
                    resp = client.get("/start?webauthn_request=" + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data["success"], True)

    @patch("fido2.cose.ES256.verify")
    def test_webauthn_verify_wrong_origin(self, mock_verify):
        self.app.conf.fido2_rp_id = "wrong.rp.id"
        mock_verify.return_value = True
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user)

        eppn = self.test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = WebauthnState(
                        {
                            "challenge": "3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc",
                            "user_verification": "preferred",
                        }
                    )
                    sess.mfa_action.webauthn_state = fido2state
                    sess.persist()
                    resp = client.get("/start?webauthn_request=" + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data["success"], False)

    @patch("fido2.cose.ES256.verify")
    def test_webauthn_verify_wrong_challenge(self, mock_verify):
        mock_verify.return_value = True
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user)

        eppn = self.test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        "challenge": "WRONG_CHALLENGE_COx1ABZEA5Odz3yejUI3AUNTQWc",
                        "user_verification": "preferred",
                    }
                    sess["testing.webauthn.state"] = json.dumps(fido2state)
                    sess.persist()
                    resp = client.get("/start?webauthn_request=" + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data["success"], False)

    @patch("fido2.cose.ES256.verify")
    def test_webauthn_verify_wrong_credential(self, mock_verify):
        req = deepcopy(SAMPLE_WEBAUTHN_REQUEST)
        req["credentialId"] = req["credentialId"].replace("0", "9")
        mock_verify.return_value = True
        # Add a working Webauthn credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user)

        eppn = self.test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        "challenge": "3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc",
                        "user_verification": "preferred",
                    }
                    sess["testing.webauthn.state"] = json.dumps(fido2state)
                    sess.persist()
                    resp = client.get("/start?webauthn_request=" + json.dumps(req))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data["success"], False)
