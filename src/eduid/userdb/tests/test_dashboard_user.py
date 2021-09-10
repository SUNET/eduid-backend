from unittest import TestCase

from eduid.userdb.credentials import CredentialList
from eduid.userdb.dashboard.user import DashboardUser
from eduid.userdb.fixtures.users import new_user_example


class TestDashboardUser(TestCase):
    def test_proper_user(self):
        userdata = new_user_example.to_dict()
        user = DashboardUser.from_dict(data=userdata)
        self.assertEqual(user.user_id, userdata['_id'])
        self.assertEqual(user.eppn, userdata['eduPersonPrincipalName'])

    def test_proper_new_user(self):
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id',)
        eppn = userdata.pop('eduPersonPrincipalName',)
        passwords = CredentialList.from_list_of_dicts(userdata['passwords'])
        user = DashboardUser(user_id=userid, eppn=eppn, credentials=passwords)
        self.assertEqual(user.user_id, userid)
        self.assertEqual(user.eppn, eppn)

    def test_missing_id(self):
        userdata = new_user_example.to_dict()
        userid = userdata.pop('_id',)
        eppn = userdata.pop('eduPersonPrincipalName',)
        passwords = CredentialList.from_list_of_dicts(userdata['passwords'])
        user = DashboardUser(eppn=eppn, credentials=passwords)
        self.assertNotEqual(user.user_id, userid)

    def test_missing_eppn(self):
        userdata = new_user_example.to_dict()
        userdata.pop('eduPersonPrincipalName',)
        with self.assertRaises(TypeError):
            DashboardUser.from_dict(userdata)
