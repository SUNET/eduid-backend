from datetime import datetime, timedelta

from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import get_short_hash
from eduid.maccapi.context import Context
from eduid.userdb.credentials import Password
from eduid.userdb.exceptions import UserDoesNotExist, UserOutOfSync
from eduid.userdb.logs.element import ManagedAccountLogElement
from eduid.userdb.maccapi import ManagedAccount
from eduid.vccs.client import VCCSClientHTTPError, VCCSPasswordFactor, VCCSRevokeFactor


class UnableToCreateUniqueEppn(Exception):
    pass


class UnableToAddPassword(Exception):
    pass


def list_users(context: Context, data_owner: str) -> list[ManagedAccount]:
    managed_accounts: list[ManagedAccount] = context.db.get_users(data_owner=data_owner)
    context.logger.info(f"Listing {managed_accounts.__len__()} users")
    return managed_accounts


def add_password(context: Context, managed_account: ManagedAccount, password: str) -> bool:
    vccs = context.vccs_client

    _vccs_version = "NDNv2" if context.config.password_v2_upgrade_enabled else "NDNv1"
    new_factor = VCCSPasswordFactor(password=password, credential_id=str(ObjectId()), version=_vccs_version)

    if not vccs.add_credentials(str(managed_account.user_id), [new_factor]):
        context.logger.error(f"Failed adding password credential {new_factor.credential_id} for user {managed_account}")
        return False
    context.logger.info(f"Added password credential {new_factor.credential_id} for user {managed_account}")

    _version = 2 if context.config.password_v2_upgrade_enabled else 1
    _password = Password(
        credential_id=new_factor.credential_id,
        salt=new_factor.salt,
        is_generated=True,
        created_by="maccapi",
        version=_version,
    )
    managed_account.credentials.add(_password)

    return True


def revoke_passwords(context: Context, managed_account: ManagedAccount, reason: str) -> bool:
    vccs = context.vccs_client

    revoke_factors = []
    for password in managed_account.credentials.filter(Password):
        credential_id = str(password.key)
        factor = VCCSRevokeFactor(credential_id=credential_id, reason=reason, reference=context.config.app_name)
        context.logger.debug(f"Revoking password credential {credential_id} for user {managed_account}")
        revoke_factors.append(factor)
        managed_account.credentials.remove(password.key)

    userid = str(managed_account.user_id)

    try:
        vccs.revoke_credentials(userid, revoke_factors)
    except VCCSClientHTTPError:
        # Should probably not happen since managed account only have one password credential
        context.logger.error(f"Failed revoking password for user {managed_account}")
        return False
    return True


def save_and_sync_user(context: Context, managed_account: ManagedAccount) -> None:
    context.logger.debug(f"Saving and syncing user {managed_account}")
    result = context.db.save(managed_account)
    context.logger.debug(f"Saved user {managed_account} with result {result}")


def generate_ma_eppn(context: Context) -> str:
    for _ in range(10):
        eppn = f"ma-{get_short_hash(8)}"
        try:
            context.db.get_user_by_eppn(eppn)
        except UserDoesNotExist:
            return eppn
    context.logger.critical("Failed to generate unique eppn")
    raise UnableToCreateUniqueEppn("Failed to generate unique eppn")


def create_and_sync_user(
    context: Context, given_name: str, surname: str, password: str, data_owner: str
) -> ManagedAccount:
    eppn = generate_ma_eppn(context=context)

    expiration: datetime = utc_now() + timedelta(days=context.config.log_retention_days)
    managed_account = ManagedAccount(
        eppn=eppn, given_name=given_name, surname=surname, data_owner=data_owner, expire_at=expiration
    )

    if not add_password(context=context, managed_account=managed_account, password=password):
        context.logger.error(f"Failed adding password for user {managed_account}")
        raise UnableToAddPassword(f"Failed adding password for user {managed_account}")

    try:
        save_and_sync_user(context=context, managed_account=managed_account)
    except UserOutOfSync as e:
        revoke_passwords(
            context=context, managed_account=managed_account, reason="UserOutOfSync during create_and_sync_user"
        )
        context.logger.error(f"Failed saving user {managed_account} due to {e}")
        raise e

    context.logger.info(f"Created user {managed_account}")
    return managed_account


def deactivate_user(context: Context, eppn: str, data_owner: str) -> ManagedAccount:
    managed_account: ManagedAccount = context.db.get_user_by_eppn(eppn)
    if managed_account is None:
        raise UserDoesNotExist(f"User {eppn} not found")
    if managed_account.data_owner != data_owner:
        raise UserDoesNotExist(f"User {eppn} not found")
    managed_account.terminated = utc_now()
    revoke_passwords(context=context, managed_account=managed_account, reason="User deactivated")
    save_and_sync_user(context=context, managed_account=managed_account)
    context.logger.info(f"Deactivated user {managed_account}")
    return managed_account


def replace_password(context: Context, eppn: str, new_password: str) -> None:
    managed_account: ManagedAccount = context.db.get_user_by_eppn(eppn)
    if managed_account is None:
        raise UserDoesNotExist(f"User {eppn} not found")
    revoke_passwords(context=context, managed_account=managed_account, reason="Password replaced")
    if not add_password(context=context, managed_account=managed_account, password=new_password):
        context.logger.error(f"Failed to add password for {managed_account}")
        raise UnableToAddPassword(f"Failed to add password for {managed_account}")
    save_and_sync_user(context=context, managed_account=managed_account)
    context.logger.info(f"Replaced password for {managed_account}")


def get_user(context: Context, eppn: str, data_owner: str) -> ManagedAccount:
    managed_account: ManagedAccount = context.db.get_user_by_eppn(eppn)
    if managed_account is None:
        raise UserDoesNotExist(f"User {eppn} not found")
    if managed_account.data_owner != data_owner:
        raise UserDoesNotExist(f"User {eppn} not found")
    return managed_account


def add_api_event(context: Context, eppn: str, action: str, action_by: str, data_owner: str) -> None:
    expiration: datetime = utc_now() + timedelta(days=context.config.log_retention_days)
    log_element = ManagedAccountLogElement(
        eppn=eppn,
        created_by=context.name,
        action=action,
        action_by=action_by,
        expire_at=expiration,
        data_owner=data_owner,
    )
    context.audit_log.save(log_element=log_element)
