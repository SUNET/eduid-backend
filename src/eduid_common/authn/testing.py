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
import logging

from bson import ObjectId

import vccs_client
from eduid_userdb.credentials import Password
from eduid_userdb.dashboard import DashboardLegacyUser, DashboardUser

from eduid_common.api.decorators import deprecated
from eduid_common.authn import get_vccs_client

logger = logging.getLogger()


class FakeVCCSClient(vccs_client.VCCSClient):
    def __init__(self, fake_response=None):
        self.fake_response = fake_response

    def _execute_request_response(self, _service, _values):
        if self.fake_response is not None:
            return json.dumps(self.fake_response)

        fake_response = {}
        if _service == 'add_creds':
            fake_response = {
                'add_creds_response': {'version': 1, 'success': True,},
            }
        elif _service == 'authenticate':
            fake_response = {
                'auth_response': {'version': 1, 'authenticated': True,},
            }
        elif _service == 'revoke_creds':
            fake_response = {
                'revoke_creds_response': {'version': 1, 'success': True,},
            }
        return json.dumps(fake_response)


class TestVCCSClient(object):
    """
    Mock VCCS client for testing. It stores factors locally,
    and it only checks for the credential_id to authenticate/revoke.

    It is used as a singleton, so we can manipulate it in the tests
    before the real functions (check_password, add_credentials) use it.
    """

    @deprecated("Remove once eduid-webapp is using MockVCCSClient (just below this)")
    def __init__(self):
        self.factors = {}

    def authenticate(self, user_id, factors):
        found = False
        if user_id not in self.factors:
            logger.debug('User {!r} not found in TestVCCSClient credential store:\n{}'.format(user_id, self.factors))
            return False
        for factor in factors:
            logger.debug(
                'Trying to authenticate user {} with factor {} (id {})'.format(user_id, factor, factor.credential_id)
            )
            fdict = factor.to_dict('auth')
            for stored_factor in self.factors[user_id]:
                if factor.credential_id != stored_factor.credential_id:
                    logger.debug(
                        'No match for id of stored factor {} (id {})'.format(stored_factor, stored_factor.credential_id)
                    )
                    continue
                logger.debug('Found matching credential_id: {}'.format(stored_factor))
                try:
                    sdict = stored_factor.to_dict('auth')
                except (AttributeError, ValueError):
                    # OATH token
                    found = True
                    break
                else:
                    # H1 hash comparision for password factors
                    if fdict['H1'] == sdict['H1']:
                        found = True
                        break
                    logger.debug('Hash {} did not match the expected hash {}'.format(fdict['H1'], sdict['H1']))
        logger.debug('TestVCCSClient authenticate result for user_id {}: {}'.format(user_id, found))
        return found

    def add_credentials(self, user_id, factors):
        user_factors = self.factors.get(str(user_id), [])
        user_factors.extend(factors)
        self.factors[str(user_id)] = user_factors
        return True

    def revoke_credentials(self, user_id, revoked):
        stored = self.factors.get(user_id, None)
        if stored:  # Nothing stored in test client yet
            for rfactor in revoked:
                rdict = rfactor.to_dict('revoke_creds')
                for factor in stored:
                    fdict = factor.to_dict('revoke_creds')
                    if rdict['credential_id'] == fdict['credential_id']:
                        stored.remove(factor)
                        break


# new name to import from dependent packages, so we can remove the deprecated TestVCCSClient
MockVCCSClient = TestVCCSClient


def provision_credentials(vccs_url, new_password, user, vccs=None, source='dashboard'):
    """
    This function should be used by tests only
    Provision new password to a user.
    Returns True on success.

    :param vccs_url: URL to VCCS authentication backend
    :param new_password: plaintext new password
    :param user: user object
    :type vccs_url: str
    :type user: User
    :rtype: bool
    """
    password_id = ObjectId()
    if vccs is None:
        vccs = get_vccs_client(vccs_url)
    # upgrade DashboardLegacyUser to DashboardUser
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser.from_dict(data=user._mongo_doc)

    new_factor = vccs_client.VCCSPasswordFactor(new_password, credential_id=str(password_id))

    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        return False  # something failed

    new_password = Password(credential_id=password_id, salt=new_factor.salt, application=source,)
    user.credentials.add(new_password)

    return user
