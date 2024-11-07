import copy
from datetime import datetime, timedelta
from unittest import TestCase
from uuid import uuid4

import bson
from pydantic import ValidationError

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.actions.tou import ToUUser
from eduid.userdb.credentials import CredentialList
from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.event import Event, EventList
from eduid.userdb.exceptions import UserMissingData
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.tou import ToUEvent, ToUList
from eduid.userdb.user import User

__author__ = "ft"


_one_dict = {
    "event_id": str(bson.ObjectId()),
    "event_type": "tou_event",
    "version": "1",
    "created_by": "test",
    "created_ts": datetime.fromisoformat("2015-09-24T01:01:01.111111+00:00"),
}

_two_dict = {
    "event_id": str(uuid4()),
    "event_type": "tou_event",
    "version": "2",
    "created_by": "test",
    "created_ts": datetime.fromisoformat("2015-09-24T02:02:02.222222+00:00"),
    "modified_ts": datetime.fromisoformat("2018-09-25T02:02:02.222222+00:00"),
}

_three_dict = {
    "event_id": str(bson.ObjectId()),
    "event_type": "tou_event",
    "version": "3",
    "created_by": "test",
    "created_ts": datetime.fromisoformat("2015-09-24T03:03:03.333333+00:00"),
    "modified_ts": datetime.fromisoformat("2015-09-24T03:03:03.333333+00:00"),
}


class TestToUEvent(TestCase):
    def setUp(self) -> None:
        self.empty: EventList = EventList()
        self.one = ToUList.from_list_of_dicts([_one_dict])
        self.two = ToUList.from_list_of_dicts([_one_dict, _two_dict])
        self.three = ToUList.from_list_of_dicts([_one_dict, _two_dict, _three_dict])

    def test_key(self) -> None:
        """
        Test that the 'key' property (used by ElementList) works for the ToUEvent.
        """
        event = self.two.to_list()[0]
        self.assertEqual(event.key, event.event_id)

    def test_parse_cycle(self) -> None:
        """
        Tests that we output something we parsed back into the same thing we output.
        """
        for this in [self.one, self.two, self.three]:
            this_dict = this.to_list_of_dicts()
            new_list = ToUList.from_list_of_dicts(this_dict)
            assert new_list.to_list_of_dicts() == this.to_list_of_dicts()

    def test_created_by(self) -> None:
        this = Event.from_dict(dict(created_by=None, event_type="test_event"))
        this.created_by = "unit test"
        self.assertEqual(this.created_by, "unit test")

    def test_event_type(self) -> None:
        this = self.one.to_list()[0]
        self.assertEqual(this.event_type, "tou_event")

    def test_reaccept_tou(self) -> None:
        three_years = timedelta(days=3 * 365)
        one_day = timedelta(days=1)
        # set modified_ts to both sides of three years ago
        _two_dict["modified_ts"] = utc_now() - three_years + one_day
        _three_dict["modified_ts"] = utc_now() - three_years - one_day
        assert isinstance(_two_dict["modified_ts"], datetime)
        assert _two_dict["modified_ts"] + three_years > utc_now()
        assert isinstance(_three_dict["modified_ts"], datetime)
        assert _three_dict["modified_ts"] + three_years < utc_now()

        # check if the TOU needs to be accepted with an interval of three years
        tl = ToUList.from_list_of_dicts([_two_dict, _three_dict])
        self.assertTrue(tl.has_accepted(version="2", reaccept_interval=int(three_years.total_seconds())))
        self.assertFalse(tl.has_accepted(version="3", reaccept_interval=int(three_years.total_seconds())))


class TestTouUser(TestCase):
    user: User

    def setUp(self) -> None:
        self.user = UserFixtures().new_user_example

    def test_proper_user(self) -> None:
        userdata = self.user.to_dict()
        userdata["tou"] = [copy.deepcopy(_one_dict)]
        user = ToUUser.from_dict(data=userdata)
        self.assertEqual(user.tou.to_list_of_dicts()[0]["version"], "1")

    def test_proper_new_user(self) -> None:
        one = copy.deepcopy(_one_dict)
        tou = ToUList.from_list_of_dicts([one])
        userdata = self.user.to_dict()
        userid = userdata.pop("_id")
        eppn = userdata.pop("eduPersonPrincipalName")
        passwords = CredentialList.from_list_of_dicts(userdata["passwords"])
        user = ToUUser(user_id=userid, eppn=eppn, tou=tou, credentials=passwords)
        self.assertEqual(user.tou.to_list_of_dicts()[0]["version"], "1")

    def test_proper_new_user_no_id(self) -> None:
        one = copy.deepcopy(_one_dict)
        tou = ToUList(elements=[ToUEvent.from_dict(one)])
        userdata = self.user.to_dict()
        passwords = CredentialList.from_list_of_dicts(userdata["passwords"])
        with self.assertRaises(ValidationError):
            ToUUser(tou=tou, credentials=passwords)  # type: ignore[call-arg]

    def test_proper_new_user_no_eppn(self) -> None:
        one = copy.deepcopy(_one_dict)
        tou = ToUList.from_list_of_dicts([one])
        userdata = self.user.to_dict()
        userid = userdata.pop("_id")
        passwords = CredentialList.from_list_of_dicts(userdata["passwords"])
        with self.assertRaises(ValidationError):
            ToUUser(user_id=userid, tou=tou, credentials=passwords)  # type: ignore[call-arg]

    def test_missing_eppn(self) -> None:
        one = copy.deepcopy(_one_dict)
        tou = ToUList.from_list_of_dicts([one])
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=TUserDbDocument({"tou": tou, "userid": self.user.user_id}))

    def test_missing_userid(self) -> None:
        one = copy.deepcopy(_one_dict)
        tou = ToUEvent.from_dict(one)
        with self.assertRaises(UserMissingData):
            ToUUser.from_dict(data=TUserDbDocument({"tou": [tou], "eppn": self.user.eppn}))
