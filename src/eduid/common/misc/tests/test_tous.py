# -*- coding: utf-8 -*-
import unittest

from eduid.common.misc.tous import get_tous

__author__ = 'lundberg'


class TouTests(unittest.TestCase):
    def test_get_tous(self):
        assert get_tous(version='test-version', languages=['en']) == {'en': 'test tou english'}
        assert get_tous(version='test-version', languages=['en', 'sv']) == {
            'en': 'test tou english',
            'sv': 'test tou svenska',
        }
        assert get_tous(version='non_existant_version', languages=['en', 'sv']) == {}
