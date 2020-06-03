# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.security.helpers import SecurityMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(SecurityMsg.stale_reauthn.value, 'security.stale_authn_info')
        self.assertEqual(SecurityMsg.rm_verified.value, 'nins.verified_no_rm')
        self.assertEqual(SecurityMsg.rm_success.value, 'nins.success_removal')
        self.assertEqual(SecurityMsg.already_exists.value, 'nins.already_exists')
        self.assertEqual(SecurityMsg.add_success.value, 'nins.successfully_added')
        self.assertEqual(SecurityMsg.max_tokens.value, 'security.u2f.max_allowed_tokens')
        self.assertEqual(SecurityMsg.max_webauthn.value, 'security.webauthn.max_allowed_tokens')
        self.assertEqual(SecurityMsg.missing_data.value, 'security.u2f.missing_enrollment_data')
        self.assertEqual(SecurityMsg.u2f_registered.value, 'security.u2f_register_success')
        self.assertEqual(SecurityMsg.no_u2f.value, 'security.u2f.no_token_found')
        self.assertEqual(SecurityMsg.no_challenge.value, 'security.u2f.missing_challenge_data')
        self.assertEqual(SecurityMsg.no_token.value, 'security.u2f.missing_token')
        self.assertEqual(SecurityMsg.long_desc.value, 'security.u2f.description_to_long')
        self.assertEqual(SecurityMsg.rm_u2f_success.value, 'security.u2f-token-removed')
        self.assertEqual(SecurityMsg.no_pdata.value, 'security.webauthn-missing-pdata')
        self.assertEqual(SecurityMsg.webauthn_success.value, 'security.webauthn_register_success')
        self.assertEqual(SecurityMsg.no_last.value, 'security.webauthn-noremove-last')
        self.assertEqual(SecurityMsg.rm_webauthn.value, 'security.webauthn-token-removed')
        self.assertEqual(SecurityMsg.no_webauthn.value, 'security.webauthn-token-notfound')
