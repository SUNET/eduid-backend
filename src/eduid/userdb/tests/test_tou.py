import copy
from datetime import datetime, timedelta
from unittest import TestCase
from uuid import uuid4

import bson

from eduid.userdb.actions.tou import ToUUser
from eduid.userdb.credentials import CredentialList
from eduid.userdb.event import Event, EventList
from eduid.userdb.exceptions import UserMissingData
from eduid.userdb.fixtures.users import new_user_example
from eduid.userdb.tou import ToUEvent, ToUList

__author__ = 'ft'

_one_dict = {
    'event_id': str(bson.ObjectId()),
    'event_type': 'tou_event',
    'version': '1',
    'created_by': 'test',
    'created_ts': datetime.fromisoformat('2015-09-24T01:01:01.111111+00:00'),
}

_two_dict = {
    'event_id': str(uuid4()),
    'event_type': 'tou_event',
    'version': '2',
    'created_by': 'test',
    'created_ts': datetime.fromisoformat('2015-09-24T02:02:02.222222+00:00'),
    'modified_ts': datetime.fromisoformat('2018-09-25T02:02:02.222222+00:00'),
}

_three_dict = {
    'event_id': str(bson.ObjectId()),
    'event_type': 'tou_event',
    'version': '3',
    'created_by': 'test',
    'created_ts': datetime.fromisoformat('2015-09-24T03:03:03.333333+00:00'),
    'modified_ts': datetime.fromisoformat('2015-09-24T03:03:03.333333+00:00'),
}


class TestToUEvent(TestCase):
    def setUp(self):
        self.empty = EventList()
        self.one = ToUList.from_list_of_dicts([_one_dict])
        self.two = ToUList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = ToUList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

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
            new_list = ToUList.from_list_of_dicts(this_dict)
            assert new_list.to_list_of_dicts() == this.to_list_of_dicts()

    def test_created_by(self):
        this = Event.from_dict(dict(created_by=None, event_type='test_event'))
        this.created_by = 'unit test'
        self.assertEqual(this.created_by, 'unit test')

    def test_event_type(self):
        this = self.one.to_list()[0]
        self.assertEqual(this.event_type, 'tou_event')

    def test_reaccept_tou(self):
        three_years = timedelta(days=3 * 365)
        self.assertGreater(_two_dict['modified_ts'] - _two_dict['created_ts'], three_years)
        self.assertLess(_three_dict['modified_ts'] - _three_dict['created_ts'], three_years)

        tl = ToUList.from_list_of_dicts([_two_dict, _three_dict])
        self.assertTrue(tl.has_accepted(version='2', reaccept_interval=int(three_years.total_seconds())))
        self.assertFalse(tl.has_accepted(version='3', reaccept_interval=int(three_years.total_seconds())))


USERID = '123467890123456789014567'
EPPN = 'hubba-bubba'


class TestTouUser(TestCase):
    def test_proper_user(self):
        userdata = new_user_example.to_dict()
        userdata['tou'] = [copy.deepcopy(_one_dict)]
        user = ToUUser.from_dict(data=userdata)
        self.assertEqual(user.tou.to_list_of_dicts()[0]['version'], '1')

    def test_proper_new_user(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList.from_list_of_dicts([one])
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id',)
        eppn = userdata.pop('eduPersonPrincipalName',)
        passwords = CredentialList.from_list_of_dicts(userdata['passwords'])
        user = ToUUser(user_id=userid, eppn=eppn, tou=tou, credentials=passwords)
        self.assertEqual(user.tou.to_list_of_dicts()[0]['version'], '1')

    def test_proper_new_user_no_id(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList(elements=[ToUEvent.from_dict(one)])
        userdata = new_user_example.to_dict()
        passwords = CredentialList.from_list_of_dicts(userdata['passwords'])
        with self.assertRaises(TypeError):
            ToUUser(tou=tou, credentials=passwords)

    def test_proper_new_user_no_eppn(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList.from_list_of_dicts([one])
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id',)
        passwords = CredentialList.from_list_of_dicts(userdata['passwords'])
        with self.assertRaises(TypeError):
            ToUUser(user_id=userid, tou=tou, credentials=passwords)

    def test_missing_eppn(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUList.from_list_of_dicts([one])
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=dict(tou=tou, userid=USERID))

    def test_missing_userid(self):
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent.from_dict(one)
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=dict(tou=[tou], eppn=EPPN))
