# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.eidas.helpers import EidasMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(EidasMsg.authn_context_mismatch.value, 'eidas.authn_context_mismatch')
        self.assertEqual(EidasMsg.reauthn_expired.value, 'eidas.reauthn_expired')
        self.assertEqual(EidasMsg.token_not_in_creds.value, 'eidas.token_not_in_credentials_used')
        self.assertEqual(EidasMsg.nin_not_matching.value, 'eidas.nin_not_matching')
        self.assertEqual(EidasMsg.verify_success.value, 'eidas.token_verify_success')
        self.assertEqual(EidasMsg.nin_already_verified.value, 'eidas.nin_already_verified')
        self.assertEqual(EidasMsg.nin_verify_success.value, 'eidas.nin_verify_success')
        self.assertEqual(EidasMsg.no_redirect_url.value, 'eidas.no_redirect_url')
        self.assertEqual(EidasMsg.action_completed.value, 'actions.action-completed')
        self.assertEqual(EidasMsg.token_not_found.value, 'eidas.token_not_found')
