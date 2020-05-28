# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.security.helpers import SecurityMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(SecurityMsg.out_of_sync.value), 'user-out-of-sync')
        self.assertEqual(str(SecurityMsg.stale_reauthn.value), 'security.stale_authn_info')
        self.assertEqual(str(SecurityMsg.rm_verified.value), 'nins.verified_no_rm')
        self.assertEqual(str(SecurityMsg.rm_success.value), 'nins.success_removal')
        self.assertEqual(str(SecurityMsg.temp_problem.value), 'Temporary technical problems')
        self.assertEqual(str(SecurityMsg.already_exists.value), 'nins.already_exists')
        self.assertEqual(str(SecurityMsg.add_success.value), 'nins.successfully_added')
        self.assertEqual(str(SecurityMsg.max_tokens.value), 'security.u2f.max_allowed_tokens')
        self.assertEqual(str(SecurityMsg.max_webauthn.value), 'security.webauthn.max_allowed_tokens')
        self.assertEqual(str(SecurityMsg.missing_data.value), 'security.u2f.missing_enrollment_data')
        self.assertEqual(str(SecurityMsg.u2f_registered.value), 'security.u2f_register_success')
        self.assertEqual(str(SecurityMsg.no_u2f.value), 'security.u2f.no_token_found')
        self.assertEqual(str(SecurityMsg.no_challenge.value), 'security.u2f.missing_challenge_data')
        self.assertEqual(str(SecurityMsg.no_token.value), 'security.u2f.missing_token')
        self.assertEqual(str(SecurityMsg.long_desc.value), 'security.u2f.description_to_long')
        self.assertEqual(str(SecurityMsg.rm_u2f_success.value), 'security.u2f-token-removed')
        self.assertEqual(str(SecurityMsg.no_pdata.value), 'security.webauthn-missing-pdata')
        self.assertEqual(str(SecurityMsg.webauthn_success.value), 'security.webauthn_register_success')
        self.assertEqual(str(SecurityMsg.no_last.value), 'security.webauthn-noremove-last')
        self.assertEqual(str(SecurityMsg.rm_webauthn.value), 'security.webauthn-token-removed')
        self.assertEqual(str(SecurityMsg.no_webauthn.value), 'security.webauthn-token-notfound')
