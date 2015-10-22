from unittest import TestCase

import copy
import bson

import eduid_userdb.exceptions
from eduid_userdb.actions.action import Action

__author__ = 'eperez'

_action_dict = {
    '_id': bson.ObjectId('234567890123456789012301'),
    'user_oid': bson.ObjectId('123467890123456789014567'),
    'action': 'accept_tou',
    'session': 'xyz',
    'preference': 100,
    'params': {
        'version': '2014-v2'
        }
    }


class TestAction(TestCase):

    def test_proper_action(self):
        action_dict = copy.copy(_action_dict)
        action = Action(data=action_dict)
        self.assertEquals(action.action_id, bson.ObjectId('234567890123456789012301'))
        self.assertEquals(action.user_id, bson.ObjectId('123467890123456789014567'))
        self.assertEquals(action.action_type, 'accept_tou')
        self.assertEquals(action.session, 'xyz')
        self.assertEquals(action.preference, 100)
        self.assertEquals(action.params, {'version': '2014-v2'})

    def test_proper_action_params(self):
        action = Action(action_id = _action_dict['_id'],
                        user_oid = _action_dict['user_oid'],
                        action_type = _action_dict['action'],
                        preference = _action_dict['preference'],
                        session = _action_dict['session'],
                        params = _action_dict['params'])
        self.assertEquals(action.action_id, bson.ObjectId('234567890123456789012301'))
        self.assertEquals(action.user_id, bson.ObjectId('123467890123456789014567'))
        self.assertEquals(action.action_type, 'accept_tou')
        self.assertEquals(action.session, 'xyz')
        self.assertEquals(action.preference, 100)
        self.assertEquals(action.params, {'version': '2014-v2'})
        self.assertEquals(action.to_dict(), _action_dict)

    def test_proper_action_no_id(self):
        action_dict = copy.copy(_action_dict)
        del action_dict['_id']
        action = Action(data=action_dict)
        self.assertEquals(type(action.action_id), bson.ObjectId)

    def test_proper_action_no_bson_id(self):
        action_dict = copy.copy(_action_dict)
        action_dict['_id'] = '234567890123456789012301'
        action = Action(data=action_dict)
        self.assertEquals(action.action_id, bson.ObjectId('234567890123456789012301'))

    def test_action_to_dict(self):
        action_dict = copy.copy(_action_dict)
        action = Action(data=action_dict)
        self.assertEquals(action_dict, action.to_dict())

    def test_action_missing_user(self):
        action_dict = copy.copy(_action_dict)
        del action_dict['user_oid']
        with self.assertRaises(eduid_userdb.exceptions.ActionMissingData):
            Action(data=action_dict)

    def test_action_missing_action(self):
        action_dict = copy.copy(_action_dict)
        del action_dict['action']
        with self.assertRaises(eduid_userdb.exceptions.ActionMissingData):
            Action(data=action_dict)

    def test_action_raise_on_unknown(self):
        action_dict = copy.copy(_action_dict)
        action_dict['ho'] = 'ho ho'
        with self.assertRaises(eduid_userdb.exceptions.ActionHasUnknownData):
            action = Action(data=action_dict)

    def test_action_dont_raise_on_unknown(self):
        action_dict = copy.copy(_action_dict)
        action_dict['ho'] = 'ho ho'
        action = Action(data=action_dict, raise_on_unknown=False)
        self.assertEquals(action.to_dict()['ho'], 'ho ho')

    def test_action_repr(self):
        action_dict = copy.copy(_action_dict)
        action = Action(data=action_dict, raise_on_unknown=False)
        self.assertEquals(repr(action), '<eduID Action: accept_tou for 123467890123456789014567>')
        self.assertEquals(str(action), '<eduID Action: accept_tou for 123467890123456789014567>')

    def test_action_equals(self):
        action_dict_1 = copy.copy(_action_dict)
        action_dict_2 = copy.copy(_action_dict)
        action_dict_2['preference'] = 200
        action1 = Action(data=action_dict_1, raise_on_unknown=False)
        action2 = Action(data=action_dict_2, raise_on_unknown=False)
        self.assertTrue(action1 != action2)
        with self.assertRaises(TypeError):
            action1 == 42
