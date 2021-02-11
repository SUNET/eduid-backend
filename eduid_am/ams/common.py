#
# Copyright (c) 2019 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
__author__ = 'eperez'

from abc import ABC, abstractmethod
from typing import List

import bson
from celery.utils.log import get_task_logger

from eduid_common.config.workers import AmConfig
from eduid_userdb.userdb import UserDB

logger = get_task_logger(__name__)


class AttributeFetcher(ABC):

    whitelist_set_attrs: List[str]
    whitelist_unset_attrs: List[str]

    def __init__(self, worker_config: AmConfig):
        if not isinstance(worker_config, AmConfig):
            raise TypeError('AttributeFetcher config should be AmConfig')
        self.conf = worker_config
        self.private_db = self.get_user_db(worker_config.mongo_uri)

    @classmethod
    @abstractmethod
    def get_user_db(cls, mongo_uri: str) -> UserDB:
        '''
        return an instance of the subclass of eduid_userdb.userdb.UserDB
        corresponding to the database holding the data to be fetched.
        '''

    def fetch_attrs(self, user_id: bson.ObjectId) -> dict:
        """
        Read a user from the Dashboard private private_db and return an update
        dict to let the Attribute Manager update the use in the central
        eduid user database.
        """

        attributes = {}
        logger.debug('Trying to get user with _id: {} from {}.'.format(user_id, self.private_db))
        user = self.private_db.get_user_by_id(user_id)
        logger.debug('User: {} found.'.format(user))

        user_dict = user.to_dict()

        # white list of valid attributes for security reasons
        attributes_set = {}
        attributes_unset = {}
        for attr in self.whitelist_set_attrs:
            value = user_dict.get(attr, None)
            if value:
                attributes_set[attr] = value
            elif attr in self.whitelist_unset_attrs:
                attributes_unset[attr] = value

        logger.debug('Will set attributes: {}'.format(attributes_set))
        logger.debug('Will remove attributes: {}'.format(attributes_unset))

        if attributes_set:
            attributes['$set'] = attributes_set
        if attributes_unset:
            attributes['$unset'] = attributes_unset

        return attributes
