#
# Copyright (c) 2019 SUNET
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
from datetime import timedelta

from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState, ResetPasswordEmailState, ResetPasswordStateDB
from eduid.userdb.testing import MongoTestCase


class TestResetPasswordStateDB(MongoTestCase):
    def setUp(self):
        super().setUp()
        self.resetpw_db = ResetPasswordStateDB(self.tmp_db.uri, 'eduid_reset_password')

    def test_email_state(self):
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba", email_address="johnsmith@example.com", email_code="dummy-code"
        )

        self.resetpw_db.save(email_state)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        self.assertEqual(state.email_address, "johnsmith@example.com")
        self.assertEqual(state.email_code.code, "dummy-code")
        self.assertEqual(state.method, "email")

        self.assertTrue(state.email_code.is_expired(timedelta(0)))
        self.assertFalse(state.email_code.is_expired(timedelta(1)))

    def test_email_state_get_by_code(self):
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba", email_address="johnsmith@example.com", email_code="dummy-code"
        )

        self.resetpw_db.save(email_state)

        state = self.resetpw_db.get_state_by_email_code("dummy-code")
        self.assertEqual(state.email_address, "johnsmith@example.com")
        self.assertEqual(state.method, "email")
        self.assertEqual(state.eppn, "hubba-bubba")
        self.assertEqual(state.generated_password, False)

    def test_email_state_generated_pw(self):
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba", email_address="johnsmith@example.com", email_code="dummy-code"
        )

        email_state.generated_password = True
        self.resetpw_db.save(email_state)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        self.assertEqual(state.email_address, "johnsmith@example.com")
        self.assertEqual(state.generated_password, True)

    def test_email_state_extra_security(self):
        email_state = ResetPasswordEmailState(
            eppn="hubba-bubba", email_address="johnsmith@example.com", email_code="dummy-code"
        )

        email_state.extra_security = {'phone_numbers': [{'number': '+99999999999', 'primary': True, 'verified': True}]}
        self.resetpw_db.save(email_state)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        self.assertEqual(state.email_address, "johnsmith@example.com")
        self.assertEqual(state.extra_security['phone_numbers'][0]['number'], '+99999999999')

    def test_email_and_phone_state(self):
        email_state = ResetPasswordEmailAndPhoneState(
            eppn="hubba-bubba",
            email_address="johnsmith@example.com",
            email_code="dummy-code",
            phone_number="+99999999999",
            phone_code="dummy-phone-code",
        )

        self.resetpw_db.save(email_state)

        state = self.resetpw_db.get_state_by_eppn("hubba-bubba")
        self.assertEqual(state.email_address, "johnsmith@example.com")
        self.assertEqual(state.email_code.code, "dummy-code")
        self.assertEqual(state.phone_number, "+99999999999")
        self.assertEqual(state.phone_code.code, "dummy-phone-code")
        self.assertEqual(state.method, "email_and_phone")
