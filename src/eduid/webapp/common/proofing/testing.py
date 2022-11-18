# -*- coding: utf-8 -*-
from typing import Optional

from flask.testing import FlaskClient

from eduid.userdb.credentials import FidoCredential
from eduid.userdb.identity import IdentityElement
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.testing import EduidAPITestCase, logger

__author__ = "lundberg"


class ProofingTests(EduidAPITestCase):
    def load_app(self, config):
        raise NotImplementedError("Subclass must implement this method")

    def _verify_status(
        self,
        finish_url: str,
        frontend_action: Optional[str],
        frontend_state: Optional[str],
        method: str,
        browser: Optional[FlaskClient] = None,
        expect_error: bool = False,
        expect_msg: Optional[TranslatableMsg] = None,
    ) -> None:
        if browser is None:
            browser = self.browser

        with browser.session_transaction() as sess:  # type: ignore
            csrf_token = sess.get_csrf_token()

        app_name, authn_id = finish_url.split("/")[-2:]

        assert app_name == self.app.conf.app_name

        logger.debug(f"Verifying status for request {authn_id}")

        req = {"authn_id": authn_id, "csrf_token": csrf_token}
        response = browser.post("/get_status", json=req)
        expected_payload = {
            "frontend_action": frontend_action,
            "frontend_state": frontend_state,
            "method": method,
            "error": expect_error,
        }
        if expect_msg:
            expected_payload["status"] = expect_msg.value
        self._check_success_response(response, type_=None, payload=expected_payload)

    def _verify_user_parameters(
        self,
        eppn: str,
        identity: Optional[IdentityElement] = None,
        identity_present: bool = True,
        identity_verified: bool = False,
        locked_identity: Optional[IdentityElement] = None,
        num_mfa_tokens: int = 1,
        num_proofings: int = 0,
        token_verified: bool = False,
    ):
        """This function is used to verify a user's parameters at the start of a test case,
        and then again at the end to ensure the right set of changes occurred to the user in the database.
        """
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        user_mfa_tokens = user.credentials.filter(FidoCredential)

        # Check token status
        assert len(user_mfa_tokens) == num_mfa_tokens, "Unexpected number of FidoCredentials on user"
        if user_mfa_tokens:
            assert user_mfa_tokens[0].is_verified == token_verified, "User token unexpected is_verified"
        assert self.app.proofing_log.db_count() == num_proofings, "Unexpected number of proofings in db"

        if identity is not None:
            # Check parameters of a specific nin
            user_identity = user.identities.find(identity.identity_type)
            if not identity_present:
                assert (
                    user_identity is None or user_identity.unique_value != identity.unique_value
                ) is True, f"identity {identity} not expected to be present on user"
                return None
            assert user_identity is not None, f"identity {identity} not present on user"
            assert (
                user_identity.unique_value == identity.unique_value
            ), "user_identity.unique_value != identity.unique_value"
            assert (
                user_identity.is_verified == identity_verified
            ), f"{user_identity} was expected to be verified={identity_verified}"

        if locked_identity is not None:
            # Check parameters of a specific locked nin
            user_locked_identity = user.locked_identity.find(locked_identity.identity_type)
            assert user_locked_identity is not None, f"locked identity {locked_identity} not present"
            assert (
                user_locked_identity.unique_value == locked_identity.unique_value
            ), f"locked identity {user_locked_identity.unique_value} not matching {locked_identity.unique_value}"
