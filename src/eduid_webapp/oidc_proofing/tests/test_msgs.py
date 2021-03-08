# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.oidc_proofing.helpers import OIDCMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(OIDCMsg.no_conn.value, 'No connection to authorization endpoint')
