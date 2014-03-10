from datetime import datetime
from copy import deepcopy

from bson import ObjectId

from eduid_am.db import MongoDB
from eduid_am.userdb import UserDB
from eduid_am.user import User


MONGO_URI_TEST = 'mongodb://localhost:27017/eduid_dashboard_test'
MONGO_URI_AM_TEST = 'mongodb://localhost:27017/eduid_am_test'

MOCKED_USER_STANDARD = {
    '_id': ObjectId('012345678901234567890123'),
    'givenName': 'John',
    'sn': 'Smith',
    'displayName': 'John Smith',
    'norEduPersonNIN': ['123456789013'],
    'photo': 'https://pointing.to/your/photo',
    'preferredLanguage': 'en',
    'eduPersonEntitlement': [
        'urn:mace:eduid.se:role:admin',
        'urn:mace:eduid.se:role:student',
    ],
    'maxReachedLoa': 3,
    'mobile': [{
        'mobile': '609609609',
        'verified': True
    }, {
        'mobile': '+34 6096096096',
        'verified': False
    }],
    'mail': 'johnsmith@example.com',
    'mailAliases': [{
        'email': 'johnsmith@example.com',
        'verified': True,
    }, {
        'email': 'johnsmith2@example.com',
        'verified': True,
    }],
    'passwords': [{
        'id': ObjectId('112345678901234567890123'),
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
    }],
    'postalAddress': [{
        'type': 'home',
        'country': 'SE',
        'address': "Long street, 48",
        'postalCode': "123456",
        'locality': "Stockholm",
        'verified': True,
    }, {
        'type': 'work',
        'country': 'ES',
        'address': "Calle Ancha, 49",
        'postalCode': "123456",
        'locality': "Punta Umbria",
        'verified': False,
    }],
}

INITIAL_VERIFICATIONS = [{
    '_id': ObjectId('234567890123456789012301'),
    'code': '9d392c',
    'model_name': 'mobile',
    'obj_id': '+34 6096096096',
    'user_oid': ObjectId("012345678901234567890123"),
    'timestamp': datetime.utcnow(),
    'verified': False,
}, {
    '_id': ObjectId(),
    'code': '123123',
    'model_name': 'norEduPersonNIN',
    'obj_id': '210987654321',
    'user_oid': ObjectId("012345678901234567890123"),
    'timestamp': datetime.utcnow(),
    'verified': False,
}, {
    '_id': ObjectId(),
    'code': '123124',
    'model_name': 'norEduPersonNIN',
    'obj_id': '123456789013',
    'user_oid': ObjectId("012345678901234567890123"),
    'timestamp': datetime.utcnow(),
    'verified': True,
}, {
    '_id': ObjectId(),
    'code': '123124',
    'model_name': 'norEduPersonNIN',
    'obj_id': '123456789050',
    'user_oid': ObjectId("012345678901234567890123"),
    'timestamp': datetime.utcnow(),
    'verified': False,
}]


class MockedUserDB(UserDB):

    test_users = {
        'johnsmith@example.com': MOCKED_USER_STANDARD,
        'johnsmith@example.org': deepcopy(MOCKED_USER_STANDARD),
    }
    test_users['johnsmith@example.org']['mail'] = 'johnsmith@example.org'
    test_users['johnsmith@example.org']['mailAliases'][0]['email'] = 'johnsmith@example.org'
    test_users['johnsmith@example.org']['mailAliases'][1]['email'] = 'johnsmith2@example.org'
    test_users['johnsmith@example.org']['_id'] = ObjectId('901234567890123456789012')
    test_users['johnsmith@example.org']['norEduPersonNIN'] = []

    def __init__(self, users=[]):
        for user in users:
            if user.get('mail', '') in self.test_users:
                self.test_users[user['mail']].update(user)

    def get_user(self, userid):
        if userid not in self.test_users:
            raise self.UserDoesNotExist
        return User(deepcopy(self.test_users.get(userid)))

    def all_users(self):
        for user in self.test_users.values():
            yield User(deepcopy(user))

    def all_userdocs(self):
        for user in self.test_users.values():
            yield deepcopy(user)


def get_db(settings):
    mongo_replicaset = settings.get('mongo_replicaset', None)
    if mongo_replicaset is not None:
        mongodb = MongoDB(db_uri=settings['mongo_uri'],
                          replicaSet=mongo_replicaset)
    else:
        mongodb = MongoDB(db_uri=settings['mongo_uri'])
    return mongodb.get_database()
