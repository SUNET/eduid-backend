from unittest import TestCase

import bson
import copy
import datetime

import eduid_userdb.exceptions
import eduid_userdb.element
from eduid_userdb.event import Event, EventList
from eduid_userdb.tou import ToUEvent
from eduid_userdb.actions.tou import ToUUser
from eduid_userdb.exceptions import UserMissingData, UserHasUnknownData

__author__ = 'ft'

_one_dict = \
    {'id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '1',
     'created_by': 'test',
     'created_ts': datetime.datetime(2015, 9, 24, 01, 01, 01, 111111),
     }

_two_dict = \
    {'id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '2',
     'created_by': 'test',
     'created_ts': datetime.datetime(2015, 9, 24, 02, 02, 02, 222222),
     }

_three_dict = \
    {'id': bson.ObjectId(),
     'event_type': 'tou_event',
     'version': '3',
     'created_by': 'test',
     'created_ts': datetime.datetime(2015, 9, 24, 03, 03, 03, 333333),
     }


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
        with self.assertRaises(eduid_userdb.exceptions.BadEvent):
            this.version = None

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts(mixed_format=True)
            eventlist_again = EventList(this_dict)
            self.assertEqual(eventlist_again.to_list_of_dicts(mixed_format=True),
                             this.to_list_of_dicts(mixed_format=True))

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
        this = Event(application=None, event_id=bson.ObjectId(), event_type='test_event')
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_by = False

    def test_created_ts_is_required(self):
        """
        Test that ToUEvent require created_ts, although Event does not.
        """
        with self.assertRaises(eduid_userdb.exceptions.BadEvent):
            ToUEvent(application='unit test',
                     created_ts=None,
                     version='foo',
                     event_id=bson.ObjectId(),
                     )

    def test_created_ts_is_required(self):
        """
        Test bad 'version'.
        """
        with self.assertRaises(eduid_userdb.exceptions.BadEvent):
            ToUEvent(application='unit test',
                     created_ts=True,
                     version=False,
                     event_id=bson.ObjectId(),
                     )

    def test_modify_created_ts(self):
        this = self.three.to_list()[-1]
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = None
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError):
            this.created_ts = True

    def test_event_type(self):
        this = self.one.to_list()[0]
        self.assertEqual(this.event_type, 'tou_event')

    def test_bad_event_type(self):
        this = self.one.to_list()[0]
        with self.assertRaises(eduid_userdb.exceptions.UserDBValueError) as cm:
            this.event_type = 1
        exc = cm.exception
        self.assertEqual(exc.reason, "Invalid 'event_type': 1")


USERID = '123467890123456789014567'


class TestTouUser(TestCase):

    def test_proper_user(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent(data = one, raise_on_unknown = False)
        user = ToUUser(userid=USERID, tou=[tou])
        self.assertEquals(user.tou.to_list_of_dicts()[0]['version'], '1')

    def test_missing_userid(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent(data = one, raise_on_unknown = False)
        with self.assertRaises(UserMissingData):
            user = ToUUser(tou=[tou])

    def test_missing_tou(self):
        with self.assertRaises(UserMissingData):
            user = ToUUser(userid=USERID)

    def test_unknown_data(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent(data = one, raise_on_unknown = False)
        data = dict(_id=USERID, tou=[tou], foo='bar')
        with self.assertRaises(UserHasUnknownData):
            user = ToUUser(data=data)

    def test_unknown_data_dont_raise(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent(data = one, raise_on_unknown = False)
        data = dict(_id=USERID, tou=[tou], foo='bar')
        user = ToUUser(data=data, raise_on_unknown=False)
        self.assertEquals(user.to_dict()['foo'], 'bar')
