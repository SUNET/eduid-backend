from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any
from unittest import TestCase

import bson
import pytest
from pydantic import ValidationError

import eduid.userdb.element
import eduid.userdb.exceptions
from eduid.common.testing_base import normalised_data
from eduid.userdb import PhoneNumber
from eduid.userdb.event import EventList
from eduid.userdb.tou import ToUEvent

__author__ = "ft"

_one_dict = {
    "id": "111111111111111111111111",  # Keep 'id' instead of event_id to test compatibility code
    "event_type": "tou_event",
    "version": "1",
    "created_by": "test",
    "created_ts": datetime.fromisoformat("2015-09-24T01:01:01.111111+00:00"),
    "modified_ts": datetime.fromisoformat("2015-09-24T01:01:01.111111+00:00"),
}

_two_dict = {
    "event_id": "222222222222222222222222",
    "event_type": "tou_event",
    "version": "2",
    "created_by": "test",
    "created_ts": datetime.fromisoformat("2015-09-24T02:02:02.222222+00:00"),
    "modified_ts": datetime.fromisoformat("2018-09-25T02:02:02.222222+00:00"),
}

_three_dict = {
    "event_id": "333333333333333333333333",
    "event_type": "tou_event",
    "version": "3",
    "created_by": "test",
    "created_ts": datetime.fromisoformat("2015-09-24T03:03:03.333333+00:00"),
    "modified_ts": datetime.fromisoformat("2015-09-24T03:03:03.333333+00:00"),
}


class SomeEventList(EventList[ToUEvent]):
    """EventList is an ABC, so make a subclass of it just for tests in this module."""

    @classmethod
    def from_list_of_dicts(cls: type[SomeEventList], items: list[dict[str, Any]]) -> SomeEventList:
        return cls(elements=[ToUEvent.from_dict(this) for this in items])


class TestEventList(TestCase):
    def setUp(self):
        self.empty = SomeEventList()
        self.one = SomeEventList.from_list_of_dicts([_one_dict])
        self.two = SomeEventList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = SomeEventList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with pytest.raises(ValidationError):
            SomeEventList(elements="bad input data")
        with pytest.raises(ValidationError):
            SomeEventList(elements=["bad input data"])

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        _one_dict_copy = deepcopy(_one_dict)  # Update id to event_id before comparing dicts
        _one_dict_copy["event_id"] = _one_dict_copy.pop("id")
        self.assertEqual([_one_dict_copy], self.one.to_list_of_dicts())

    def test_find(self):
        match = self.one.find(self.one.to_list()[0].key)
        self.assertIsInstance(match, ToUEvent)
        self.assertEqual(match.version, _one_dict["version"])

    def test_add(self):
        second = self.two.to_list()[-1]
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_duplicate_key(self):
        data = deepcopy(_two_dict)
        data["version"] = "other version"
        dup = ToUEvent.from_dict(data)
        with pytest.raises(ValidationError) as exc_info:
            self.two.add(dup)

        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "ctx": {"error": ValueError("Duplicate element key: '222222222222222222222222'")},
                    "loc": ("elements",),
                    "msg": "Value error, Duplicate element key: '222222222222222222222222'",
                    "type": "value_error",
                }
            ]
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_add_event(self):
        third = self.three.to_list_of_dicts()[-1]
        this = SomeEventList.from_list_of_dicts([_one_dict, _two_dict, third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_add_wrong_type(self):
        new = PhoneNumber(number="+4612345678")
        with pytest.raises(ValidationError):
            self.one.add(new)

    def test_remove(self):
        self.three.remove(self.three.to_list()[-1].key)
        now_two = self.three
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid.userdb.exceptions.UserDBValueError):
            self.one.remove("+46709999999")

    def test_unknown_event_type(self):
        e1 = {
            "event_type": "unknown_event",
            "id": str(bson.ObjectId()),
        }

        with pytest.raises(ValidationError) as exc_info:
            SomeEventList.from_list_of_dicts([e1])

        assert normalised_data(exc_info.value.errors(), exclude_keys=["input", "url"]) == normalised_data(
            [
                {
                    "loc": ("created_by",),
                    "msg": "Field required",
                    "type": "missing",
                },
                {
                    "loc": ("version",),
                    "msg": "Field required",
                    "type": "missing",
                },
            ],
        ), f"Wrong error message: {exc_info.value.errors()}"

    def test_modified_ts_addition(self):
        _event_no_modified_ts = {
            "event_type": "tou_event",
            "version": "1",
            "created_by": "test",
            "created_ts": datetime(2015, 9, 24, 1, 1, 1, 111111),
        }
        self.assertNotIn("modified_ts", _event_no_modified_ts)
        el = SomeEventList.from_list_of_dicts([_event_no_modified_ts])
        assert el.count == 1
        for event in el.to_list_of_dicts():
            # As long as the _no_modified_ts_in_db property exists on Element, we expect
            # there to be no modified_ts in the output dict when there was none in the
            # input dict. Written this way to be obvious what needs to change in this test
            # case when _no_modified_ts_in_db is removed from Element.
            if el.to_list()[0].no_modified_ts_in_db:
                assert "modified_ts" not in event
            else:
                self.assertIsInstance(event["modified_ts"], datetime)
                assert event["modified_ts"] == event["created_ts"]
        for event in el.to_list():
            self.assertIsInstance(event.modified_ts, datetime)

    def test_update_modified_ts(self):
        _event_modified_ts = {
            "event_type": "tou_event",
            "version": "1",
            "created_by": "test",
            "created_ts": datetime(2015, 9, 24, 1, 1, 1, 111111),
            "modified_ts": datetime(2015, 9, 24, 1, 1, 1, 111111),
        }
        self.assertIn("modified_ts", _event_modified_ts)
        el = SomeEventList.from_list_of_dicts([_event_modified_ts])
        event = el.to_list()[0]

        self.assertIsInstance(event.modified_ts, datetime)
        self.assertEqual(event.modified_ts, event.created_ts)

        event.modified_ts = datetime(2018, 9, 24, 1, 1, 1, 111111)
        self.assertIsInstance(event.modified_ts, datetime)
        self.assertEqual(event.modified_ts, datetime(2018, 9, 24, 1, 1, 1, 111111))
        self.assertNotEqual(event.modified_ts, event.created_ts)
