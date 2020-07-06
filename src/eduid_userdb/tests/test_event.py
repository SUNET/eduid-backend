import datetime
from copy import deepcopy
from unittest import TestCase

import bson

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.element import Element
from eduid_userdb.event import EventList
from eduid_userdb.tou import ToUEvent, ToUList

__author__ = 'ft'

_one_dict = {
    'id': bson.ObjectId(),  # Keep 'id' instead of event_id to test compatiblity code
    'event_type': 'tou_event',
    'version': '1',
    'created_by': 'test',
    'created_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
    'modified_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
}

_two_dict = {
    'event_id': bson.ObjectId(),
    'event_type': 'tou_event',
    'version': '2',
    'created_by': 'test',
    'created_ts': datetime.datetime(2015, 9, 24, 2, 2, 2, 222222),
    'modified_ts': datetime.datetime(2018, 9, 25, 2, 2, 2, 222222),
}

_three_dict = {
    'event_id': bson.ObjectId(),
    'event_type': 'tou_event',
    'version': '3',
    'created_by': 'test',
    'created_ts': datetime.datetime(2015, 9, 24, 3, 3, 3, 333333),
    'modified_ts': datetime.datetime(2015, 9, 24, 3, 3, 3, 333333),
}


class TestEventList(TestCase):
    def setUp(self):
        self.empty = EventList([])
        self.one = EventList([_one_dict])
        self.two = EventList([_one_dict, _two_dict])
        self.three = EventList([_one_dict, _two_dict, _three_dict])

    def test_init_bad_data(self):
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            EventList('bad input data')

    def test_to_list(self):
        self.assertEqual([], self.empty.to_list(), list)
        self.assertIsInstance(self.one.to_list(), list)

        self.assertEqual(1, len(self.one.to_list()))

    def test_to_list_of_dicts(self):
        self.assertEqual([], self.empty.to_list_of_dicts(), list)

        _one_dict_copy = deepcopy(_one_dict)  # Update id to event_id before comparing dicts
        _one_dict_copy['event_id'] = _one_dict_copy.pop('id')
        _one_dict_copy['data'] = None
        self.assertEqual([_one_dict_copy], self.one.to_list_of_dicts(mixed_format=True))

    def test_find(self):
        match = self.one.find(self.one.to_list()[0].key)
        self.assertIsInstance(match, ToUEvent)
        self.assertEqual(match.version, _one_dict['version'])

    def test_add(self):
        second = self.two.to_list()[-1]
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_identical_duplicate(self):
        old_len = self.two.count
        dup = self.two.to_list()[-1]
        self.two.add(dup)
        self.assertEqual(old_len, self.two.count)

    def test_add_duplicate_key(self):
        data = deepcopy(_two_dict)
        data['version'] = 'other version'
        dup = ToUEvent.from_dict(data)
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_event(self):
        third = self.three.to_list()[-1]
        this = EventList([_one_dict, _two_dict, third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_add_wrong_type(self):
        elemdict = {
            'id': bson.ObjectId(),
        }
        new = Element.from_dict(elemdict)
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            self.one.add(new)

    def test_remove(self):
        now_two = self.three.remove(self.three.to_list()[-1].key)
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('+46709999999')

    def test_unknown_event_type(self):
        e1 = {
            'event_type': 'unknown_event',
            'id': bson.ObjectId(),
        }
        with self.assertRaises(eduid_userdb.exceptions.BadEvent) as cm:
            EventList([e1])
        exc = cm.exception
        self.assertIn('Unknown event_type', exc.reason)

    def test_modified_ts_addition(self):
        _event_no_modified_ts = {
            'event_id': bson.ObjectId(),
            'event_type': 'tou_event',
            'version': '1',
            'created_by': 'test',
            'created_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
        }
        self.assertNotIn('modified_ts', _event_no_modified_ts)
        el = EventList([_event_no_modified_ts])
        for event in el.to_list_of_dicts():
            self.assertIsInstance(event['modified_ts'], datetime.datetime)
            self.assertEqual(event['modified_ts'], event['created_ts'])
        for event in el.to_list():
            self.assertIsInstance(event.modified_ts, datetime.datetime)
            self.assertEqual(event.modified_ts, event.created_ts)

    def test_update_modified_ts(self):
        _event_modified_ts = {
            'event_id': bson.ObjectId(),
            'event_type': 'tou_event',
            'version': '1',
            'created_by': 'test',
            'created_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
            'modified_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
        }
        self.assertIn('modified_ts', _event_modified_ts)
        el = EventList([_event_modified_ts])
        event = el.to_list()[0]

        self.assertIsInstance(event.modified_ts, datetime.datetime)
        self.assertEqual(event.modified_ts, event.created_ts)

        event.modified_ts = datetime.datetime(2018, 9, 24, 1, 1, 1, 111111)
        self.assertIsInstance(event.modified_ts, datetime.datetime)
        self.assertEqual(event.modified_ts, datetime.datetime(2018, 9, 24, 1, 1, 1, 111111))
        self.assertNotEqual(event.modified_ts, event.created_ts)

    def test_loading_duplicate_tou_events(self):
        data = [
            {
                "event_id": bson.ObjectId("5699fdbed300e400155be719"),
                "version": "2014-v1",
                "created_ts": datetime.datetime.fromisoformat("2016-01-16T08:22:22.520"),
                "created_by": "signup",
            },
            {
                "event_id": bson.ObjectId("581c3084df7c670064b583d6"),
                "version": "2016-v1",
                "created_ts": datetime.datetime.fromisoformat("2016-11-04T06:53:56.217"),
                "created_by": "eduid_tou_plugin",
            },
            {
                "event_id": bson.ObjectId("581c308e70971c006488d7d7"),
                "version": "2016-v1",
                "created_ts": datetime.datetime.fromisoformat("2016-11-04T06:54:06.676"),
                "created_by": "eduid_tou_plugin",
            },
        ]
        el = ToUList(data)
        self.assertEqual(el.count, 2)
