from eduid_userdb.testing import MongoTestCase, MOCKED_USER_STANDARD as M
from eduid_userdb.exceptions import MultipleUsersReturned, UserDoesNotExist
from bson import ObjectId
import eduid_userdb

from eduid_am.celery import celery, get_attribute_manager


class TestTasks(MongoTestCase):

    def setUp(self):
        super(TestTasks, self).setUp(celery, get_attribute_manager)

    def test_get_user_by_id(self):
        user = self.amdb.get_user_by_id(M['_id'])
        self.assertEqual(user.mail_addresses.primary.email, M['mail'])
        with self.assertRaises(UserDoesNotExist):
            self.amdb.get_user_by_id('123456789012')

    def test_get_user_by_mail(self):
        user = self.amdb.get_user_by_mail(M['mailAliases'][0]['email'])
        self.assertEqual(user.user_id, M['_id'])

        # Test unverified mail address in mailAliases, should raise UserDoesNotExist
        with self.assertRaises(UserDoesNotExist):
            self.amdb.get_user_by_mail(M['mailAliases'][2]['email'], raise_on_missing=True)

    def test_user_duplication_exception(self):
        user1 = self.amdb.get_user_by_mail(M['mail'])
        user2_doc = user1.to_dict()
        user2_doc['_id'] = ObjectId()  # make up a new unique identifier
        del user2_doc['modified_ts']   # defeat sync-check mechanism
        self.amdb.save(eduid_userdb.User(data=user2_doc))
        with self.assertRaises(MultipleUsersReturned):
            self.amdb.get_user_by_mail(M['mail'])
