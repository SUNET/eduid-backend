from unittest import TestCase
import copy

from eduid_userdb.signup.user import SignupUser
from eduid_userdb.data_samples import NEW_SIGNUP_USER_EXAMPLE


class TestSignupUser(TestCase):
    def test_proper_user(self):
        userdata = copy.deepcopy(NEW_SIGNUP_USER_EXAMPLE)
        user = SignupUser(data=userdata)
        self.assertEqual(user.user_id, userdata['_id'])
        self.assertEqual(user.eppn, userdata['eduPersonPrincipalName'])

    def test_proper_new_user(self):
        userdata = copy.deepcopy(NEW_SIGNUP_USER_EXAMPLE)
        userid = userdata.pop('_id')
        eppn = userdata.pop('eduPersonPrincipalName')
        user = SignupUser.construct_user(userid=userid, eppn=eppn)
        self.assertEqual(user.user_id, userid)
        self.assertEqual(user.eppn, eppn)

    def test_missing_id(self):
        userdata = copy.deepcopy(NEW_SIGNUP_USER_EXAMPLE)
        userid = userdata.pop('_id')
        eppn = userdata.pop('eduPersonPrincipalName')
        user = SignupUser.construct_user(eppn=eppn)
        self.assertNotEqual(user.user_id, userid)

    def test_missing_eppn(self):
        userdata = copy.deepcopy(NEW_SIGNUP_USER_EXAMPLE)
        userid = userdata.pop('_id')
        userdata.pop('eduPersonPrincipalName')
        with self.assertRaises(KeyError):
            SignupUser.construct_user(userid=userid)
