# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.personal_data.helpers import PDataMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(PDataMsg.out_of_sync.value), 'user-out-of-sync')
        self.assertEqual(str(PDataMsg.save_success.value), 'pd.save-success')
        self.assertEqual(str(PDataMsg.required.value), 'pdata.field_required')
