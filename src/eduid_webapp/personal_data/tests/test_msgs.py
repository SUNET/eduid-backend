# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.personal_data.helpers import PDataMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        assert PDataMsg.save_success.value == 'pd.save-success'
        assert PDataMsg.required.value == 'pdata.field_required'
        assert PDataMsg.special_chars.value == 'only allow letters'
