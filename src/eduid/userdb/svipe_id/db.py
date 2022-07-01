# -*- coding: utf-8 -*-

from typing import Any, Mapping

from eduid.userdb import UserDB
from eduid.userdb.svipe_id.user import SvipeIdUser

__author__ = 'lundberg'


class SvipeIdUserDB(UserDB[SvipeIdUser]):
    def __init__(self, db_uri: str, db_name: str = 'eduid_svipe_id', collection: str = 'profiles'):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: Mapping[str, Any]) -> SvipeIdUser:
        return SvipeIdUser.from_dict(data)
