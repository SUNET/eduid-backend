import copy
from unittest import TestCase

import bson
from pydantic import ValidationError

from eduid.userdb.actions.action import Action

__author__ = 'eperez'

_action_dict = {
    '_id': bson.ObjectId('234567890123456789012301'),
    'eppn': 'hubba-bubba',
    'action': 'accept_tou',
    'session': 'xyz',
    'preference': 100,
    'params': {'version': '2014-v2'},
    'result': None,
}


class TestAction(TestCase):
    def test_proper_action(self):
        action_dict = copy.copy(_action_dict)
        action = Action.from_dict(action_dict)
        self.assertEqual(action.action_id, bson.ObjectId('234567890123456789012301'))
        self.assertEqual(action.eppn, 'hubba-bubba')
        self.assertEqual(action.action_type, 'accept_tou')
        self.assertEqual(action.session, 'xyz')
        self.assertEqual(action.preference, 100)
        self.assertEqual(action.params, {'version': '2014-v2'})

    def test_proper_action_params(self):
        action = Action(
            action_id=_action_dict['_id'],
            eppn=_action_dict['eppn'],
            action_type=_action_dict['action'],
            preference=_action_dict['preference'],
            session=_action_dict['session'],
            params=_action_dict['params'],
        )
        self.assertEqual(action.action_id, bson.ObjectId('234567890123456789012301'))
        self.assertEqual(action.eppn, 'hubba-bubba')
        self.assertEqual(action.action_type, 'accept_tou')
        self.assertEqual(action.session, 'xyz')
        self.assertEqual(action.preference, 100)
        self.assertEqual(action.params, {'version': '2014-v2'})
        self.assertEqual(action.to_dict(), _action_dict)

    def test_proper_action_no_id(self):
        action_dict = copy.copy(_action_dict)
        del action_dict['_id']
        action = Action.from_dict(action_dict)
        self.assertEqual(type(action.action_id), bson.ObjectId)

    def test_action_to_dict(self):
        action_dict = copy.copy(_action_dict)
        action = Action.from_dict(action_dict)
        self.assertEqual(action_dict, action.to_dict())

    def test_action_missing_user(self):
        action_dict = copy.copy(_action_dict)
        del action_dict['eppn']
        with self.assertRaises(ValidationError):
            Action.from_dict(action_dict)

    def test_action_missing_action(self):
        action_dict = copy.copy(_action_dict)
        del action_dict['action']
        with self.assertRaises(ValidationError):
            Action.from_dict(action_dict)

    def test_action_repr(self):
        action_dict = copy.copy(_action_dict)
        action = Action.from_dict(action_dict)
        self.assertIsInstance(repr(action), str)

    def test_action_equals(self):
        action_dict_1 = copy.copy(_action_dict)
        action_dict_2 = copy.copy(_action_dict)
        action_dict_2['preference'] = 200
        action1 = Action.from_dict(action_dict_1)
        action2 = Action.from_dict(action_dict_2)
        self.assertTrue(action1 != action2)
