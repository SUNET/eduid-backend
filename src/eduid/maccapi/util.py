import logging

from uuid import uuid4
from pwgen import pwgen
import math


from eduid.userdb.exceptions import UserDoesNotExist
from eduid.maccapi.model.user import ManagedAccount
from eduid.maccapi.context import Context
from eduid.maccapi.userdb import ManagedAccountDB

logger = logging.getLogger(__name__)

def get_short_hash(entropy=8):
    return uuid4().hex[:entropy]

def generate_ma_eppn(context: Context) -> str:
    # TODO: check for existing eppn
    for _ in range(10):
        eppn = f"ma-{get_short_hash(8)}"
        try:
            context.db.get_user_by_eppn(eppn)
        except UserDoesNotExist:
            return eppn
    context.logger.critical("Failed to generate unique eppn")
    raise Exception("Failed to generate unique eppn")


def generate_password(length: int = 12) -> str:
    password = pwgen(int(length), no_capitalize=True, no_symbols=True)
    password = " ".join([password[i * 4 : i * 4 + 4] for i in range(0, math.ceil(len(password) / 4))])

    return password

def save_and_sync_user(context: Context, managed_account: ManagedAccount):
    context.logger.debug(f"Saving and syncing user {managed_account}")
    result = context.db.save(managed_account)
    context.logger.debug(f"Saved user {managed_account} with result {result}")



