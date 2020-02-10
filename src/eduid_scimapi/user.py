from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Dict, Optional


@dataclass
class User(object):
    user_id: str
    username: str
    external_id: str
    name: Mapping[str, str]
    version: int
    created: datetime
    last_modified: datetime

    @property
    def etag(self):
        return f'W\/"{self.version}"'
    
    def to_dict(self, location: str):
        res = {
            'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id': self.user_id,
            'externalId': self.external_id,
            'meta':{
                'resourceType':'User',
                'created': self.created.isoformat(),
                'lastModified': self.last_modified.isoformat(),
                'location': location,
                'version': self.etag,
            },
            'name': self.name,
            'userName': self.username,
        }
        return res


class UserStore(object):

    def __init__(self):
        self._data: Dict[str, User] = {}

    def add_user(self, user: User):
        self._data[user.user_id] = user

    def get_user_by_username(self, username: str) -> Optional[User]:
        for user in self._data.values():
            if user.username == username:
                return user
        return None

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return self._data.get(user_id)
