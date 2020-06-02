# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.oidc_proofing.helpers import OIDCMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(OIDCMsg.temp_error.value, 'Temporary technical problems')
        self.assertEqual(OIDCMsg.no_conn.value, 'No connection to authorization endpoint')
        # this message comes from a ValidationError in eduid_common.api.schemas.validators,
        # and not directly used in the oidc_proofing code - just relayed
        # It is here to gather it with all other translatable messages
        self.assertEqual(OIDCMsg.nin_invalid.value, 'nin needs to be formatted as 18|19|20yymmddxxxx')
