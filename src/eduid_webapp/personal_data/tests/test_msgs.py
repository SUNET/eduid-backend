# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.personal_data.helpers import PDataMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(PDataMsg.save_success.value, 'pd.save-success')
        self.assertEqual(PDataMsg.required.value, 'pdata.field_required')
