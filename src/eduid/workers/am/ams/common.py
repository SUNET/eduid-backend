__author__ = "eperez"

from abc import ABC, abstractmethod
from typing import Any

import bson
from celery.utils.log import get_task_logger

from eduid.common.config.workers import AmConfig
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB
from eduid.userdb.util import format_dict_for_debug

logger = get_task_logger(__name__)


class AttributeFetcher(ABC):
    whitelist_set_attrs: list[str]
    whitelist_unset_attrs: list[str]

    def __init__(self, worker_config: AmConfig):
        if not isinstance(worker_config, AmConfig):
            raise TypeError("AttributeFetcher config should be AmConfig")
        self.conf = worker_config
        self.private_db: UserDB[User] | None = None
        if worker_config.mongo_uri:
            self.private_db = self.get_user_db(worker_config.mongo_uri)

    @classmethod
    @abstractmethod
    def get_user_db(cls, mongo_uri: str) -> UserDB:
        """
        return an instance of the subclass of eduid.userdb.userdb.UserDB
        corresponding to the database holding the data to be fetched.
        """

    def fetch_attrs(self, user_id: bson.ObjectId) -> dict[str, Any]:
        """
        Read a user from the Dashboard private private_db and return an update
        dict to let the Attribute Manager update the use in the central
        eduid user database.
        """

        attributes: dict[str, Any] = {}
        logger.debug(f"Trying to get user with _id: {user_id} from {self.private_db}.")
        if not self.private_db:
            raise RuntimeError("No database initialised")
        user = self.private_db.get_user_by_id(user_id)
        logger.debug(f"User: {user} found.")
        if not user:
            raise UserDoesNotExist(f"No user found with id {user_id}")

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

        logger.debug(f"Will set attributes:\n{format_dict_for_debug(attributes_set)}")
        logger.debug(f"Will remove attributes: {attributes_unset}")

        if attributes_set:
            attributes["$set"] = attributes_set
        if attributes_unset:
            attributes["$unset"] = attributes_unset

        return attributes
