import copy
from datetime import datetime
from unittest import TestCase

import bson

import eduid_userdb.exceptions
from eduid_userdb.element import Element, PrimaryElement, VerifiedElement
from eduid_userdb.exceptions import EduIDUserDBError, UserDBValueError, UserHasUnknownData


class TestElements(TestCase):

    def test_create_element(self):
        elem = Element(created_by='test')

        assert elem.created_by == 'test'
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_created_ts(self):
        now = datetime.utcnow()
        elem = Element(created_by='test', created_ts=now)

        assert elem.created_by == 'test'
        assert elem.created_ts == now
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_created_ts_bool(self):
        elem = Element(created_by='test', created_ts=True)

        assert elem.created_by == 'test'
        assert isinstance(elem.created_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_modified_ts(self):
        now = datetime.utcnow()
        elem = Element(created_by='test', modified_ts=now)

        assert elem.created_by == 'test'
        assert elem.modified_ts == now
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_modified_ts_bool(self):
        elem = Element(created_by='test', modified_ts=True)

        assert elem.created_by == 'test'
        assert isinstance(elem.modified_ts, datetime)
        assert isinstance(elem.modified_ts, datetime)

    def test_create_element_with_created_and_modified_ts(self):
        now = datetime.utcnow()
        elem = Element(created_by='test', modified_ts=now, created_ts=now)

        assert elem.created_by == 'test'
        assert elem.created_ts == now
        assert elem.modified_ts == now

    def test_element_reset_created_ts(self):
        now = datetime.utcnow()
        elem = Element(created_by='test', modified_ts=now, created_ts=now)

        with self.assertRaises(UserDBValueError):
            elem.created_ts = True

        with self.assertRaises(UserDBValueError):
            elem.created_ts = datetime.utcnow()

    def test_element_reset_created_by(self):
        now = datetime.utcnow()
        elem = Element(created_by='test', modified_ts=now, created_ts=now)

        with self.assertRaises(UserDBValueError):
            elem.created_by = 'new'

    def test_element_reset_modified_ts(self):
        now = datetime.utcnow()
        elem = Element(created_by='test', modified_ts=now, created_ts=now)

        then = datetime.utcnow()
        elem.modified_ts = then

        assert elem.modified_ts == then
