# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.oidc_proofing.helpers import OIDCMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(OIDCMsg.temp_error.value), 'Temporary technical problems')
        self.assertEqual(str(OIDCMsg.no_conn.value), 'No connection to authorization endpoint')
        self.assertEqual(str(OIDCMsg.nin_invalid.value), 'nin needs to be formatted as 18|19|20yymmddxxxx')
