from unittest import TestCase

import bson
import datetime

import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.event import EventList
from eduid_userdb.tou import ToUEvent, ToUList
from eduid_userdb.credentials import Password
from copy import deepcopy

__author__ = 'ft'

_one_dict = \
    {'event_id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '1',
     'created_by': 'test',
     'created_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
     'modified_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
     }

_two_dict = \
    {'event_id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '2',
     'created_by': 'test',
     'created_ts': datetime.datetime(2015, 9, 24, 2, 2, 2, 222222),
     'modified_ts': datetime.datetime(2018, 9, 25, 2, 2, 2, 222222),
     }

_three_dict = \
    {'event_id': bson.ObjectId(),
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

        self.assertEqual([_one_dict], self.one.to_list_of_dicts(mixed_format=True))

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
        dup = ToUEvent(data = data)
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_event(self):
        third = self.three.to_list()[-1]
        this = EventList([_one_dict, _two_dict, third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_add_wrong_type(self):
        pwdict = {'id': bson.ObjectId(),
                  'salt': 'foo',
                  }
        new = Password(data=pwdict)
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            self.one.add(new)

    def test_remove(self):
        now_two = self.three.remove(self.three.to_list()[-1].key)
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('+46709999999')

    def test_unknown_event_type(self):
        e1 = {'event_type': 'unknown_event',
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

    def test_reaccept_tou(self):
        three_years = 94608000  # seconds
        self.assertGreater(_two_dict['modified_ts'] - _two_dict['created_ts'], datetime.timedelta(seconds=three_years))
        self.assertLess(_three_dict['modified_ts'] - _three_dict['created_ts'], datetime.timedelta(seconds=three_years))

        tl = ToUList([_two_dict, _three_dict])
        self.assertTrue(tl.has_accepted(version='2', reaccept_interval=three_years))
        self.assertFalse(tl.has_accepted(version='3', reaccept_interval=three_years))

