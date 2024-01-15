from bson import ObjectId
from eduid.common.misc.timeutil import utc_now
from eduid.maccapi.context import Context
from eduid.maccapi.model.user import ManagedAccount


from typing import List

from eduid.maccapi.util import generate_ma_eppn, logger, save_and_sync_user
from eduid.userdb.credentials import Password
from eduid.userdb.exceptions import UserOutOfSync
from eduid.vccs.client import VCCSClient, VCCSClientHTTPError, VCCSPasswordFactor, VCCSRevokeFactor


def list_users(context: Context):
    managed_accounts: List[ManagedAccount] = context.db.get_users_by_organization("foo")
    context.logger.info(f"Listing {managed_accounts.__len__()} users")
    return managed_accounts


def add_password(managed_account: ManagedAccount, password: str, vccs_url: str) -> bool:
    vccs = VCCSClient(base_url=vccs_url)
    logger.debug(f"vccs_url: {vccs_url}")

    new_factor = VCCSPasswordFactor(password=password, credential_id=str(ObjectId()))

    # TODO: add to credentials store
    if not vccs.add_credentials(str(managed_account.user_id), [new_factor]):
        logger.error(f"Failed adding password credential {new_factor.credential_id} for user {managed_account}")
        return False
    logger.info(f"Added password credential {new_factor.credential_id} for user {managed_account}")

    _password = Password(credential_id=new_factor.credential_id, salt=new_factor.salt, is_generated=True, created_by="maccapi")
    managed_account.credentials.add(_password)

    return True


def revoke_passwords(context: Context, managed_account: ManagedAccount, reason: str):
    vccs_url = context.config.vccs_url
    vccs = VCCSClient(base_url=vccs_url)
    logger.debug(f"vccs_url: {vccs_url}")

    revoke_factors = []
    for password in managed_account.credentials.filter(Password):
        credential_id = str(password.key)
        factor = VCCSRevokeFactor(credential_id=credential_id, reason=reason, reference=context.config.app_name)
        context.logger.debug(f"Revoking password credential {credential_id} for user {managed_account}")
        revoke_factors.append(factor)
        managed_account.credentials.remove(password.key)

    userid = str(managed_account.user_id)
    try:
        vccs.revoke_credentials(user_id=userid, factors=revoke_factors)
    except VCCSClientHTTPError:
        # Should probably not happen since managed account only have one password credential
        context.logger.error(f"Failed revoking password for user {managed_account}")
        return False
    return True


def create_and_sync_user(context: Context, given_name: str, surname: str, password: str) -> ManagedAccount:

    eppn = generate_ma_eppn(context=context)

    managed_account = ManagedAccount(eppn=eppn, given_name=given_name, surname=surname)

    if not add_password(managed_account=managed_account, password=password, vccs_url=context.config.vccs_url):
        context.logger.error(f"Failed adding password for user {managed_account}")
        raise Exception(f"Failed adding password for user {managed_account}")

    try:
        save_and_sync_user(context=context, managed_account=managed_account)
    except UserOutOfSync as e:
        revoke_passwords(context=context, managed_account=managed_account, reason="UserOutOfSync during create_and_sync_user")
        context.logger.error(f"Failed saving user {managed_account} due to {e}")
        raise e

    context.logger.info(f"Created user {managed_account}")
    return managed_account


def deactivate_user(context: Context, eppn: str) -> ManagedAccount:
    managed_account: ManagedAccount = context.db.get_user_by_eppn(eppn)
    if managed_account is None:
        raise Exception(f"User {eppn} not found")
    managed_account.terminated = utc_now()
    revoke_passwords(context=context, managed_account=managed_account, reason="User deactivated")
    save_and_sync_user(context=context, managed_account=managed_account)
    context.logger.info(f"Deactivated user {managed_account}")
    return managed_account


def replace_password(context: Context, eppn: str, new_password: str):
    managed_account: ManagedAccount = context.db.get_user_by_eppn(eppn)
    if managed_account is None:
        raise Exception(f"User {eppn} not found")
    revoke_passwords(context=context, managed_account=managed_account, reason="Password replaced")
    if not add_password(managed_account=managed_account, password=new_password, vccs_url=context.config.vccs_url):
        context.logger.error(f"Failed to add password for {managed_account}")
        raise Exception(f"Failed to add password for {managed_account}")
    save_and_sync_user(context=context, managed_account=managed_account)
    context.logger.info(f"Replaced password for {managed_account}")