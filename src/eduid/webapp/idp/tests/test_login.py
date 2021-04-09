import logging
import os

from mock import patch
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import requested_authn_context
from saml2.client import Saml2Client

from eduid.vccs.client import VCCSClient
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.idp.tests.test_app import IdPTests, LoginState

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class IdPTestLogin(IdPTests):
    def update_config(self, config):
        config = super().update_config(config)
        config.update({'signup_link': 'TEST-SIGNUP-LINK', 'log_level': 'DEBUG'})
        return config

    def test_display_of_login_page(self):
        next_url = '/back-to-test-marker'

        (session_id, info) = self.saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id, relay_state=next_url, binding=BINDING_HTTP_REDIRECT,
        )

        path = self._extract_path_from_info(info)

        response = self.browser.get(path)
        body = response.data.decode('utf-8')

        assert response.status_code == 200
        assert self.app.conf.signup_link in body

        # the RelayState is present as a hidden form parameter in the login page
        assert next_url in body

    def test_submitting_wrong_credentials(self):
        result = self._try_login()

        assert result.reached_state == LoginState.S2_VERIFY

        # check that we were sent back to the login screen
        redirect_loc = self._extract_path_from_response(result.response)
        assert redirect_loc.startswith('/sso/redirect?SAMLRequest=')

    def test_successful_authentication(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response)
        session_info = authn_response.session_info()
        attributes = session_info['ava']

        assert 'eduPersonPrincipalName' in attributes
        assert attributes['eduPersonPrincipalName'] == ['hubba-bubba']

    def test_ForceAuthn_with_existing_SSO_session(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response)
        session_info = authn_response.session_info()
        attributes = session_info['ava']

        assert 'eduPersonPrincipalName' in attributes
        assert attributes['eduPersonPrincipalName'] == ['hubba-bubba']

        logger.info(
            '\n\n\n\n' + '#' * 80 + '\n' + 'Logging in again with ForceAuthn="true"\n' + '#' * 80 + '\n' + '\n\n\n\n'
        )

        # Log in again, with ForceAuthn="true"
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result2 = self._try_login(force_authn=True)

        authn_response2 = self.parse_saml_authn_response(result2.response)

        # Make sure the second response isn't referring to the first login request
        assert authn_response.in_response_to != authn_response2.in_response_to

    def test_terminated_user(self):
        user = self.amdb.get_user_by_eppn(self.test_user.eppn)
        user.terminated = True
        self.amdb.save(user)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        cookie = result.response.headers['Set-Cookie']
        assert f'{self.app.conf.sso_cookie.key}=;' in cookie
        assert 'expires=Thu, 01-Jan-1970 00:00:00 GMT' in cookie

    def test_with_unknown_sp(self):
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name='UNKNOWN_SP_CONFIG')
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        assert b'SAML error: Unknown Service Provider' in result.response.data

    def test_sso_to_unknown_sp(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name='UNKNOWN_SP_CONFIG')
        saml2_client = Saml2Client(config=sp_config)

        # Don't patch VCCS here to ensure a SSO is done, not a password authentication
        result2 = self._try_login(saml2_client=saml2_client)

        assert result2.reached_state == LoginState.S0_REDIRECT
        assert b'SAML error: Unknown Service Provider' in result2.response.data
        cookies = result2.response.headers['Set-Cookie']
        # Ensure the pre-existing IdP SSO cookie wasn't touched
        assert self.app.conf.sso_cookie_name not in cookies

    def test_with_authncontext(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            # request MFA, but the test user does not have any MFA credentials
            req_authn_context = requested_authn_context('https://refeds.org/profile/mfa', comparison='exact')
            result = self._try_login(authn_context=req_authn_context)

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        assert b'Access to the requested service could not be granted.' in result.response.data

    def test_eduperson_targeted_id(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response)
        session_info = authn_response.session_info()
        attributes = session_info['ava']
        assert 'eduPersonTargetedID' in attributes
        assert attributes['eduPersonTargetedID'] == ['d537e1fd83ccd6bdb952099f5f9d32f0a015740e500921b70a3adc7ca6b4182d']
