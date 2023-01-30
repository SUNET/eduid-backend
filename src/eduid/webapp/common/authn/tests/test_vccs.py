#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
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
from typing import cast
from unittest.mock import patch

from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.testing import MongoTestCase
from eduid.userdb.user import User
from eduid.vccs.client import VCCSClient, VCCSClientHTTPError
from eduid.webapp.common.authn import vccs as vccs_module
from eduid.webapp.common.authn.testing import MockVCCSClient


class VCCSTestCase(MongoTestCase):
    user: User

    def setUp(self, **kwargs):
        super().setUp(am_users=[UserFixtures().new_user_example], **kwargs)
        self.vccs_client = cast(VCCSClient, MockVCCSClient())
        _user = self.amdb.get_user_by_mail("johnsmith@example.com")
        assert _user is not None
        self.user = _user

        # Start with no credentials
        for credential in self.user.credentials.to_list():
            self.user.credentials.remove(credential.key)
        vccs_module.add_password(self.user, new_password="abcd", application="test", vccs=self.vccs_client)

    def tearDown(self):
        vccs_module.revoke_passwords(self.user, reason="testing", application="test", vccs=self.vccs_client)
        super().tearDown()

    def _check_credentials(self, creds):
        return vccs_module.check_password(creds, self.user, vccs=self.vccs_client)

    def test_check_good_credentials(self):
        result = self._check_credentials("abcd")
        self.assertTrue(result)

    def test_check_bad_credentials(self):
        result = self._check_credentials("fghi")
        self.assertFalse(result)

    def test_add_password(self):
        added = vccs_module.add_password(self.user, new_password="wxyz", application="test", vccs=self.vccs_client)
        self.assertTrue(added)
        result1 = self._check_credentials("abcd")
        self.assertTrue(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertTrue(result3)
        self.assertFalse(result3.is_generated)

    def test_add_password_generated(self):
        added = vccs_module.add_password(
            self.user, new_password="wxyz", is_generated=True, application="test", vccs=self.vccs_client
        )
        self.assertTrue(added)
        result1 = self._check_credentials("abcd")
        self.assertTrue(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertTrue(result3)
        self.assertTrue(result3.is_generated)

    def test_change_password(self):
        added = vccs_module.change_password(
            self.user, new_password="wxyz", old_password="abcd", application="test", vccs=self.vccs_client
        )
        self.assertTrue(added)
        result1 = self._check_credentials("abcd")
        self.assertFalse(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertTrue(result3)
        self.assertFalse(result3.is_generated)

    def test_change_password_generated(self):
        added = vccs_module.change_password(
            self.user,
            new_password="wxyz",
            old_password="abcd",
            application="test",
            is_generated=True,
            vccs=self.vccs_client,
        )
        self.assertTrue(added)
        result1 = self._check_credentials("abcd")
        self.assertFalse(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertTrue(result3)
        self.assertTrue(result3.is_generated)

    def test_change_password_bad_old_password(self):
        added = vccs_module.change_password(
            self.user, new_password="wxyz", old_password="fghi", application="test", vccs=self.vccs_client
        )
        self.assertFalse(added)
        result1 = self._check_credentials("abcd")
        self.assertTrue(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertFalse(result3)

    def test_reset_password(self):
        added = vccs_module.reset_password(self.user, new_password="wxyz", application="test", vccs=self.vccs_client)
        self.assertTrue(added)
        result1 = self._check_credentials("abcd")
        self.assertFalse(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertTrue(result3)
        self.assertFalse(result3.is_generated)

    def test_reset_password_generated(self):
        added = vccs_module.reset_password(
            self.user, new_password="wxyz", application="test", is_generated=True, vccs=self.vccs_client
        )
        self.assertTrue(added)
        result1 = self._check_credentials("abcd")
        self.assertFalse(result1)
        result2 = self._check_credentials("fghi")
        self.assertFalse(result2)
        result3 = self._check_credentials("wxyz")
        self.assertTrue(result3)
        self.assertTrue(result3.is_generated)

    def test_change_password_error_adding(self):
        from eduid.webapp.common.authn.testing import MockVCCSClient

        with patch.object(MockVCCSClient, "add_credentials"):
            MockVCCSClient.add_credentials.return_value = False
            added = vccs_module.change_password(
                self.user, new_password="wxyz", old_password="abcd", application="test", vccs=self.vccs_client
            )
            self.assertFalse(added)
            result1 = self._check_credentials("abcd")
            self.assertFalse(result1)
            result2 = self._check_credentials("fghi")
            self.assertFalse(result2)
            result3 = self._check_credentials("wxyz")
            self.assertFalse(result3)

    def test_reset_password_error_revoking(self):
        from eduid.webapp.common.authn.testing import MockVCCSClient

        def mock_revoke_creds(*args):
            raise VCCSClientHTTPError("dummy", 500)

        with patch.object(MockVCCSClient, "revoke_credentials", mock_revoke_creds):
            added = vccs_module.reset_password(
                self.user, new_password="wxyz", application="test", vccs=self.vccs_client
            )
            self.assertTrue(added)
            result1 = self._check_credentials("abcd")
            self.assertFalse(result1)
            result2 = self._check_credentials("fghi")
            self.assertFalse(result2)
            result3 = self._check_credentials("wxyz")
            self.assertTrue(result3)
