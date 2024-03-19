__author__ = "eperez"

from typing import Any

from eduid.userdb.exceptions import UserMissingData
from eduid.userdb.user import User


class ToUUser(User):
    """
    Subclass of eduid.userdb.User
    """

    @classmethod
    def check_or_use_data(cls, data: dict[str, Any]) -> dict[str, Any]:
        """
        Check that the provided data dict contains all needed keys.
        """
        if "_id" not in data or data["_id"] is None:
            raise UserMissingData("Attempting to record a ToU acceptance for an unidentified user.")
        if "eduPersonPrincipalName" not in data or data["eduPersonPrincipalName"] is None:
            raise UserMissingData("Attempting to record a ToU acceptance for a user without eppn.")
        return data
