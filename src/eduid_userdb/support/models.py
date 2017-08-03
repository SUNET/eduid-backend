# -*- coding: utf-8 -*-

from __future__ import absolute_import

from copy import deepcopy

from eduid_userdb.user import User
from eduid_userdb.dashboard.user import DashboardUser
from eduid_userdb.signup.user import SignupUser

__author__ = 'lundberg'

# Models for filtering out unneeded or unwanted data from eduID database objects


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

        if _data is None:
            pass
        elif self.add_keys:
            for key in self.add_keys:
                try:
                    self[key] = _data[key]
                except KeyError:
                    pass
        elif self.remove_keys:
            for key in self.remove_keys:
                _data.pop(key, None)
            self.update(_data)
        else:
            self.update(_data)


class SupportUser(GenericFilterDict):

    remove_keys = ['_id', 'letter_proofing_data']

    def __init__(self, data):
        _data_in = User(data).to_dict()
        _user_id = _data_in['_id']
        super(SupportUser, self).__init__(_data_in)

        self['user_id'] = _user_id
        self['mailAliases'] = [MailAlias(alias) for alias in self['mailAliases']]
        self['passwords'] = [Password(password) for password in self['passwords']]
        self['tou'] = [ToU(tou) for tou in self['tou']]


class SupportDashboardUser(GenericFilterDict):

    remove_keys = ['_id', 'letter_proofing_data']

    def __init__(self, data):
        _data_in = DashboardUser(data=data).to_dict()
        _user_id = _data_in['_id']
        super(SupportDashboardUser, self).__init__(_data_in)

        self['user_id'] = _user_id
        self['mailAliases'] = [MailAlias(alias) for alias in self['mailAliases']]
        self['passwords'] = [Password(password) for password in self['passwords']]
        self['tou'] = [ToU(tou) for tou in self['tou']]


class SupportSignupUser(GenericFilterDict):

    remove_keys = ['_id', 'letter_proofing_data']

    def __init__(self, data):
        _data_in = SignupUser(data=data).to_dict()
        _user_id = _data_in['_id']
        super(SupportSignupUser, self).__init__(_data_in)

        self['user_id'] = _user_id
        self['mailAliases'] = [MailAlias(alias) for alias in self['mailAliases']]
        self['passwords'] = [Password(password) for password in self['passwords']]
        self['tou'] = [ToU(tou) for tou in self['tou']]
        self['pending_mail_address'] = PendingMailAddress(self.get('pending_mail_address'))


class MailAlias(GenericFilterDict):

    remove_keys = ['verification_code']


class PendingMailAddress(MailAlias):
    pass


class Password(GenericFilterDict):

    add_keys = ['created_by', 'created_ts']


class ToU(GenericFilterDict):

    remove_keys = ['id']


class UserAuthnInfo(GenericFilterDict):

    add_keys = ['success_ts', 'fail_count', 'success_count']


class UserVerifications(GenericFilterDict):

    add_keys = ['verified', 'obj_id', 'timestamp', 'model_name', 'verified_timestamp']


class UserActions(GenericFilterDict):

    add_keys = ['action', 'params']


class ProofingLogEntry(GenericFilterDict):

    add_keys = ['nin', 'created', 'proofing_method']


class UserLetterProofing(GenericFilterDict):

    add_keys = ['nin', 'proofing_letter']

    class Nin(GenericFilterDict):
        add_keys = ['created_ts', 'number']

    class ProofingLetter(GenericFilterDict):
        add_keys = ['sent_ts', 'is_sent', 'address']

    def __init__(self, data):
        _data = deepcopy(data)
        super(UserLetterProofing, self).__init__(_data)
        self['nin'] = self.Nin(self['nin'])
        self['proofing_letter'] = self.ProofingLetter(self['proofing_letter'])


class UserOidcProofing(GenericFilterDict):

    add_keys = ['nin', 'modified_ts', 'state']

    class Nin(GenericFilterDict):
        add_keys = ['created_ts', 'number']

    def __init__(self, data):
        _data = deepcopy(data)
        super(UserOidcProofing, self).__init__(_data)
        self['nin'] = self.Nin(self['nin'])
