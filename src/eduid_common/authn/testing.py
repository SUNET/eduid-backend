#
# Copyright (c) 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import json

from bson import ObjectId
import vccs_client
from eduid_userdb import Password
from eduid_userdb.dashboard import DashboardLegacyUser, DashboardUser


class FakeVCCSClient(vccs_client.VCCSClient):

    def __init__(self, fake_response=None):
        self.fake_response = fake_response

    def _execute_request_response(self, _service, _values):
        if self.fake_response is not None:
            return json.dumps(self.fake_response)

        fake_response = {}
        if _service == 'add_creds':
            fake_response = {
                'add_creds_response': {
                    'version': 1,
                    'success': True,
                },
            }
        elif _service == 'authenticate':
            fake_response = {
                'auth_response': {
                    'version': 1,
                    'authenticated': True,
                },
            }
        elif _service == 'revoke_creds':
            fake_response = {
                'revoke_creds_response': {
                    'version': 1,
                    'success': True,
                },
            }
        return json.dumps(fake_response)


class TestVCCSClient(object):
    '''
    Mock VCCS client for testing. It stores credentials locally,
    and it only checks for the credential_id to authenticate/revoke.

    It is used as a singleton, so we can manipulate it in the tests
    before the real functions (check_password, add_credentials) use it.
    '''
    def __init__(self):
        self.credentials = {}

    def authenticate(self, user_id, factors):
        stored = self.credentials[user_id]
        for factor in factors:
            fdict = factor.to_dict('auth')
            found = False
            for sfactor in stored:
                sdict = sfactor.to_dict('auth')
                if fdict['H1'] == sdict['H1']:
                    found = True
                    break
            if not found:
                return False
        return True

    def add_credentials(self, user_id, factors):
        self.credentials[user_id] = factors
        return True

    def revoke_credentials(self, user_id, revoked):
        stored = self.credentials[user_id]
        for rfactor in revoked:
            rdict = rfactor.to_dict('revoke_creds')
            for factor in stored:
                fdict = factor.to_dict('revoke_creds')
                if rdict['credential_id'] == fdict['credential_id']:
                    stored.remove(factor)
                    break

test_vccs = TestVCCSClient()


def get_vccs_client(vccs_url):
    """
    Instantiate a VCCS client.
    :param vccs_url: VCCS authentication backend URL
    :type vccs_url: string
    :return: vccs client
    :rtype: VCCSClient
    """
    if vccs_url == 'dummy':
        return test_vccs
    return vccs_client.VCCSClient(
        base_url=vccs_url,
    )


def provision_credentials(vccs_url, new_password, user,
                          vccs=None, source='dashboard'):
    """
    This function should be used by tests only
    Provision new password to a user.
    Returns True on success.

    :param vccs_url: URL to VCCS authentication backend
    :param old_password: plaintext current password
    :param new_password: plaintext new password
    :param user: user object
    :type vccs_url: str
    :type old_password: str
    :type user: User
    :rtype: bool
    """
    password_id = ObjectId()
    if vccs is None:
        vccs = get_vccs_client(vccs_url)
    # upgrade DashboardLegacyUser to DashboardUser
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser(data=user._mongo_doc)

    new_factor = vccs_client.VCCSPasswordFactor(new_password,
                                                credential_id=str(password_id))

    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        return False  # something failed

    new_password = Password(credential_id = password_id,
                            salt = new_factor.salt,
                            application = source,
                            )
    user.passwords.add(new_password)

    return user


HERE = os.path.abspath(os.path.dirname(__file__))


class AuthnAPITestBase(EduidAPITestCase):

    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update({
            'SAML2_LOGIN_REDIRECT_URL': '/',
            'SAML2_LOGOUT_REDIRECT_URL': '/logged-out',
            'SAML2_SETTINGS_MODULE': saml_config,
            })
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return authn_init_app('test.localhost', config)

    def add_outstanding_query(self, came_from):
        """
        Add a SAML2 authentication query to the queries cache.
        To be used before accessing the assertion consumer service.

        :param came_from: url to redirect back the client
                          after finishing with the authn service.
        :type came_from: str

        :return: the session token corresponding to the query
        :rtype: str
        """
        with self.app.test_request_context('/login'):
            response1 = self.app.dispatch_request()
            oq_cache = OutstandingQueriesCache(session)
            oq_cache.set(session.token, came_from)
            session.persist()
            return session.token

    def login(self, eppn, came_from):
        """
        Add a SAML2 authentication query to the queries cache,
        build a cookie with a session id corresponding to the added query,
        build a SAML2 authn response for the added query,
        and send both to the assertion consumer service,
        so that the user is logged in (the session corresponding to the cookie
        has her eppn).
        This method returns the cookie that has to be sent with any
        subsequent request that needs to be athenticated.

        :param eppn: the eppn of the user to be logged in
        :type eppn: str
        :param came_from: url to redirect back the client
                          after finishing with the authn service.
        :type came_from: str

        :return: the cookie corresponding to the authn session
        :rtype: str
        """
        session_id = self.add_outstanding_query(came_from)
        cookie_name = self.app.config.get('SESSION_COOKIE_NAME')
        cookie = dump_cookie(cookie_name, session_id,
                             max_age=float(self.app.config.get('PERMANENT_SESSION_LIFETIME')),
                             path=self.app.config.get('SESSION_COOKIE_PATH'),
                             domain=self.app.config.get('SESSION_COOKIE_DOMAIN'))

        saml_response = auth_response(session_id, eppn)

        with self.app.test_request_context('/saml2-acs', method='POST',
                                headers={'Cookie': cookie},
                                    data={'SAMLResponse': base64.b64encode(saml_response),
                                                 'RelayState': came_from}):
 
            response1 = self.app.dispatch_request()
            cookie = response1.headers['Set-Cookie']
            return cookie

    def authn(self, url, force_authn=False):
        """
        Common code for the tests that need to send an authentication request.
        This checks that the client is redirected to the idp.

        :param url: the url of the desired authentication mode.
        :type url: str
        :param force_authn: whether to force reauthentication for an already
                            authenticated client
        :type force_authn: bool
        """
        with self.app.test_client() as c:
            resp = c.get(url)
            authn_req = get_location(get_authn_request(self.app.config,
                                                       session, '/', None,
                                                       force_authn=force_authn))
            idp_url = authn_req.split('?')[0]
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(idp_url))

    def acs(self, url, eppn, check_fn):
        """
        common code for the tests that need to access the assertion consumer service
        and then check the side effects of this access.

        :param url: the url of the desired authentication mode.
        :type url: str
        :param eppn: the eppn of the user to access the service
        :type eppn: str
        :param check_fn: the function that checks the side effects after accessing the acs
        :type check_fn: callable
        """
        came_from = '/camefrom/'
        with self.app.test_client() as c:
            resp = c.get(url)
            cookie = resp.headers['Set-Cookie']
            token = session._session.token
            authr = auth_response(token, eppn)

        with self.app.test_request_context('/saml2-acs', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': base64.b64encode(authr),
                                                 'RelayState': came_from}):

            oq_cache = OutstandingQueriesCache(session)
            oq_cache.set(token, came_from)

            resp = self.app.dispatch_request()

            self.assertEquals(resp.status_code, 302)
            self.assertEquals(resp.location, came_from)
            check_fn()
