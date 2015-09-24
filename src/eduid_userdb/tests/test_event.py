from unittest import TestCase

import bson
import copy
import datetime

import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.event import EventList
from eduid_userdb.tou import ToUEvent

__author__ = 'ft'

_one_dict = \
    {'id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '1',
     }

_two_dict = \
    {'id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '2',
     }

_three_dict = \
    {'id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '3',
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

        self.assertEqual([_one_dict], self.one.to_list_of_dicts())

    def test_find(self):
        match = self.one.find(self.one.to_list()[0].key)
        self.assertIsInstance(match, ToUEvent)
        self.assertEqual(match.version, _one_dict['version'])

    def test_add(self):
        second = self.two.to_list()[-1]
        self.one.add(second)
        self.assertEqual(self.one.to_list_of_dicts(), self.two.to_list_of_dicts())

    def test_add_duplicate(self):
        dup = self.two.to_list()[-1]
        with self.assertRaises(eduid_userdb.element.DuplicateElementViolation):
            self.two.add(dup)

    def test_add_mailaddress(self):
        third = self.three.to_list()[-1]
        this = EventList([_one_dict, _two_dict, third])
        self.assertEqual(this.to_list_of_dicts(), self.three.to_list_of_dicts())

    def test_add_wrong_type(self):
        pwdict = {'id': bson.ObjectId(),
                  'salt': 'foo',
                  }
        new = eduid_userdb.password.Password(data=pwdict)
        with self.assertRaises(eduid_userdb.element.UserDBValueError):
            self.one.add(new)

    def test_remove(self):
        now_two = self.three.remove(self.three.to_list()[-1].key)
        self.assertEqual(self.two.to_list_of_dicts(), now_two.to_list_of_dicts())

    def test_remove_unknown(self):
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            self.one.remove('+46709999999')


class TestToUEvent(TestCase):
    def setUp(self):
        self.empty = EventList([])
        self.one = EventList([_one_dict])
        self.two = EventList([_one_dict, _two_dict])
        self.three = EventList([_one_dict, _two_dict, _three_dict])

    def test_key(self):
        """
        Test that the 'key' property (used by ElementList) works for the ToUEvent.
        """
        event = self.two.to_list()[0]
        self.assertEqual(event.key, event.id)

    def test_setting_invalid_version(self):
        this = self.one.to_list()[0]
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.version = None

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            self.assertEqual(EventList(this_dict).to_list_of_dicts(), this.to_list_of_dicts())

    def test_unknown_input_data(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        with self.assertRaises(eduid_userdb.exceptions.EventHasUnknownData):
            ToUEvent(data=one)

    def test_unknown_input_data_allowed(self):
        one = copy.deepcopy(_one_dict)
        one['foo'] = 'bar'
        addr = ToUEvent(data = one, raise_on_unknown = False)
        out = addr.to_dict()
        self.assertIn('foo', out)
        self.assertEqual(out['foo'], one['foo'])

    def test_created_by(self):
        this = self.three.to_list()[-1]
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = False

    def test_modify_created_by(self):
        this = self.three.to_list()[-1]
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = 1
        this.created_by = 'unit test'
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = 'test unit'

    def test_created_ts(self):
        this = self.three.to_list()[-1]
        this.created_ts = True
        self.assertIsInstance(this.created_ts, datetime.datetime)
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = False

    def test_modify_created_ts(self):
        this = self.three.to_list()[-1]
        this.created_ts = datetime.datetime.utcnow()
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = True

