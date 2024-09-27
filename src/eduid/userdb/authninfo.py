import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from eduid.userdb import User
from eduid.userdb.credentials import U2F, Password, Webauthn
from eduid.userdb.element import ElementKey
from eduid.userdb.userdb import BaseDB

logger = logging.getLogger(__name__)

__author__ = "eperez"


class AuthnCredType(str, Enum):
    password = "security.password_credential_type"
    u2f = "security.u2f_credential_type"
    unknown = "security.unknown_credential_type"
    webauthn = "security.webauthn_credential_type"


@dataclass
class AuthnInfoElement:
    credential_type: AuthnCredType
    created_ts: datetime
    success_ts: datetime | None


class AuthnInfoDB(BaseDB):
    """
    TODO: We already have a database class to access this collection, in the IdP. Consolidate the two.
    """

    def __init__(self, db_uri: str, db_name: str = "eduid_idp_authninfo", collection: str = "authn_info"):
        super().__init__(db_uri, db_name, collection)

    def get_authn_info(self, user: User) -> Mapping[ElementKey, AuthnInfoElement]:
        """
        :param user: User object
        :return: Mapping from credential.key to AuthnInfoElement for each user credential
        """
        authninfo = {}
        for credential in user.credentials.to_list():
            data_type = AuthnCredType.unknown
            if isinstance(credential, Password):
                data_type = AuthnCredType.password
            elif isinstance(credential, U2F):
                data_type = AuthnCredType.u2f
            elif isinstance(credential, Webauthn):
                data_type = AuthnCredType.webauthn

            auth_entry = self._coll.find_one(credential.key)
            logger.debug(f"get_authn_info {user}: cred id: {credential.key} auth entry: {auth_entry}")
            success_ts = None
            if auth_entry:
                success_ts = auth_entry["success_ts"]

            authninfo[credential.key] = AuthnInfoElement(
                credential_type=data_type, created_ts=credential.created_ts, success_ts=success_ts
            )
        return authninfo
