# -*- coding: utf-8 -*-
from enum import unique

from eduid_common.api.messages import TranslatableMsg

__author__ = 'lundberg'


@unique
class GroupManagementMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    user_does_not_exist = 'group.user_does_not_exist'
    create_failed = 'group.create_failed'
    user_not_owner = 'group.user_not_owner'
