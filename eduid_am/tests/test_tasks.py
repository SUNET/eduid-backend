from eduid_userdb.testing import MongoTestCase, MOCKED_USER_STANDARD as M
from eduid_userdb.exceptions import MultipleUsersReturned, UserDoesNotExist
from bson import ObjectId
import copy


class TestTasks(MongoTestCase):
    def test_get_user_by_id(self):
        user = self.am.get_user_by_id(M['_id'])
        self.assertEqual(user.get('mail'), M['mail'])
        user = self.am.get_user_by_id('12340987')
        self.assertEqual(user, None)
        self.assertRaises(UserDoesNotExist, self.am.get_user_by_id, '12340987', True)

    def test_get_user_by_mail(self):
        user = self.am.get_user_by_mail(M['mailAliases'][0]['email'])
        self.assertEqual(user.get('_id'), M['_id'])

        # Test unverified mail address in mailAliases, should raise UserDoesNotExist
        self.assertRaises(UserDoesNotExist, self.am.get_user_by_mail, M['mailAliases'][2]['email'], True)

    def test_user_duplication_exception(self):
        user = copy.deepcopy(M)
        user['_id'] = ObjectId()
        self.amdb.attributes.insert(user)
        self.assertRaises(MultipleUsersReturned, self.am.get_user_by_mail, M['mail'])
