# -*- coding: utf-8 -*-
from enum import unique
from typing import Optional

from eduid_common.api.messages import TranslatableMsg
from eduid_scimapi.userdb import ScimApiUser

from eduid_webapp.group_management.app import current_group_management_app as current_app

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


def get_scim_user_by_eppn(eppn: str) -> Optional[ScimApiUser]:
    external_id = f'{eppn}@{current_app.config.scim_external_id_scope}'
    return current_app.scimapi_userdb.get_user_by_external_id(external_id=external_id)
