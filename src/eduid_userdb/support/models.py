# -*- coding: utf-8 -*-

from __future__ import absolute_import

from copy import deepcopy

from eduid_userdb.user import User
from eduid_userdb.dashboard.user import DashboardUser
from eduid_userdb.signup.user import SignupUser

__author__ = 'lundberg'


class SupportUser(User):
    pass


class SupportDashboardUser(DashboardUser):
    pass


class SupportSignupUser(SignupUser):
    pass


class GenericFilterDict(dict):

    add_keys = None
    remove_keys = None

    def __init__(self, data):
        """
        Create a filtered dict with white- or blacklisting of keys

        :param data: Data to filter
        :type data: dict
        """
        _data = deepcopy(data)
        super(GenericFilterDict, self).__init__()
        if self.add_keys:
            for key in self.add_keys:
                try:
                    self[key] = _data[key]
                except KeyError:
                    pass
        elif self.remove_keys:
            for key in self.remove_keys:
                try:
                    del _data[key]
                except KeyError:
                    pass
            self.update(data)
        else:
            self.update(data)


class UserAuthnInfo(GenericFilterDict):

    add_keys = ['success_ts', 'fail_count', 'success_count']


class UserVerifications(GenericFilterDict):

    add_keys = ['verified', 'obj_id', 'timestamp', 'model_name', 'verified_timestamp']


class UserActions(GenericFilterDict):

    add_keys = ['action', 'params']


class UserIdProofingLetter(GenericFilterDict):

    add_keys = ['nin', 'proofing_letter']

    class Nin(GenericFilterDict):
        add_keys = ['created_ts', 'number']

    class ProofingLetter(GenericFilterDict):
        add_keys = ['sent_ts', 'is_sent', 'address']

    def __init__(self, data):
        _data = deepcopy(data)
        super(UserIdProofingLetter, self).__init__(_data)
        self['nin'] = self.Nin(self['nin'])
        self['proofing_letter'] = self.ProofingLetter(self['proofing_letter'])
