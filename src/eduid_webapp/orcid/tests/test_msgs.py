# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.orcid.helpers import OrcidMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(OrcidMsg.already_connected.value), 'orc.already_connected')
        self.assertEqual(str(OrcidMsg.authz_error.value), 'orc.authorization_fail')
        self.assertEqual(str(OrcidMsg.no_state.value), 'orc.unknown_state')
        self.assertEqual(str(OrcidMsg.unknown_nonce.value), 'orc.unknown_nonce')
        self.assertEqual(str(OrcidMsg.sub_mismatch.value), 'orc.sub_mismatch')
        self.assertEqual(str(OrcidMsg.authz_success.value), 'orc.authorization_success')
        self.assertEqual(str(OrcidMsg.temp_problem.value), 'Temporary technical problems')
