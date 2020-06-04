from unittest import TestCase

from eduid_userdb.fixtures.users import new_signup_user_example
from eduid_userdb.exceptions import UserMissingData
from eduid_userdb.signup.user import SignupUser


class TestSignupUser(TestCase):
    def test_proper_user(self):
        userdata = new_signup_user_example.to_dict()
        user = SignupUser.from_dict(data=userdata)
        self.assertEqual(user.user_id, userdata['_id'])
        self.assertEqual(user.eppn, userdata['eduPersonPrincipalName'])

    def test_proper_new_user(self):
        userdata = new_signup_user_example.to_dict()
        userid = userdata.pop('_id')
        eppn = userdata.pop('eduPersonPrincipalName')
        user = SignupUser.construct_user(_id=userid, eppn=eppn)
        self.assertEqual(user.user_id, userid)
        self.assertEqual(user.eppn, eppn)

    def test_missing_id(self):
        userdata = new_signup_user_example.to_dict()
        userid = userdata.pop('_id')
        eppn = userdata.pop('eduPersonPrincipalName')
        user = SignupUser.construct_user(eppn=eppn)
        self.assertNotEqual(user.user_id, userid)

    def test_missing_eppn(self):
        userdata = new_signup_user_example.to_dict()
        userid = userdata.pop('_id')
        userdata.pop('eduPersonPrincipalName')
        with self.assertRaises(UserMissingData):
            SignupUser.construct_user(_id=userid)
