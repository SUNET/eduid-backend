import copy
import datetime
from unittest import TestCase

import bson

import eduid_userdb.element
import eduid_userdb.exceptions
from eduid_userdb.actions.tou import ToUUser
from eduid_userdb.credentials import CredentialList
from eduid_userdb.event import Event, EventList
from eduid_userdb.exceptions import UserHasUnknownData, UserMissingData
from eduid_userdb.fixtures.users import new_user_example
from eduid_userdb.tou import ToUEvent, ToUList

__author__ = 'ft'

_one_dict = {
    'event_id': bson.ObjectId(),
    'event_type': 'tou_event',
    'version': '1',
    'created_by': 'test',
    'created_ts': datetime.datetime(2015, 9, 24, 1, 1, 1, 111111),
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
        self.assertEqual(event.key, event.event_id)

    def test_parse_cycle(self):
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            eventlist_again = EventList(this_dict)
            self.assertEqual(
                eventlist_again.to_list_of_dicts(), this.to_list_of_dicts()
            )

    def test_created_by(self):
        this = Event.from_dict(dict(created_by=None, event_id=bson.ObjectId(), event_type='test_event'))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_event_type(self):
        this = self.one.to_list()[0]
        self.assertEqual(this.event_type, 'tou_event')

    def test_reaccept_tou(self):
        three_years = 94608000  # seconds
        self.assertGreater(_two_dict['modified_ts'] - _two_dict['created_ts'], datetime.timedelta(seconds=three_years))
        self.assertLess(_three_dict['modified_ts'] - _three_dict['created_ts'], datetime.timedelta(seconds=three_years))

        tl = ToUList([_two_dict, _three_dict])
        self.assertTrue(tl.has_accepted(version='2', reaccept_interval=three_years))
        self.assertFalse(tl.has_accepted(version='3', reaccept_interval=three_years))


USERID = '123467890123456789014567'
EPPN = 'hubba-bubba'


class TestTouUser(TestCase):
    def test_proper_user(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent.from_dict(one)
        userdata = new_user_example.to_dict()
        userdata['tou'] = [tou]
        user = ToUUser.from_dict(data=userdata)
        self.assertEqual(user.tou.to_list_of_dicts()[0]['version'], '1')

    def test_proper_new_user(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList([ToUEvent.from_dict(one)])
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id')
        eppn = userdata.pop('eduPersonPrincipalName')
        passwords = CredentialList(userdata['passwords'])
        user = ToUUser.construct_user(_id=userid, eppn=eppn, tou=tou, passwords=passwords)
        self.assertEqual(user.tou.to_list_of_dicts()[0]['version'], '1')

    def test_proper_new_user_no_id(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList([ToUEvent.from_dict(one)])
        userdata = new_user_example.to_dict()
        passwords = CredentialList(userdata['passwords'])
        with self.assertRaises(UserMissingData):
            ToUUser.construct_user(tou=tou, passwords=passwords)

    def test_proper_new_user_no_eppn(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList([ToUEvent.from_dict(one)])
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id')
        passwords = CredentialList(userdata['passwords'])
        with self.assertRaises(UserMissingData):
            ToUUser.construct_user(userid=userid, tou=tou, passwords=passwords)

    def test_proper_new_user_no_tou(self):
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id')
        eppn = userdata.pop('eduPersonPrincipalName')
        passwords = CredentialList(userdata['passwords'])
        with self.assertRaises(UserMissingData):
            ToUUser.construct_user(_id=userid, eppn=eppn, passwords=passwords)

    def test_missing_eppn(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList([ToUEvent.from_dict(one)])
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=dict(tou=tou, userid=USERID))

    def test_missing_userid(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent.from_dict(one)
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=dict(tou=[tou], eppn=EPPN))

    def test_missing_tou(self):
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=dict(eppn=EPPN, userid=USERID))
