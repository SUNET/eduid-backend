import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import cast

from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Password
from eduid.userdb.element import ElementKey
from eduid.userdb.user import User
from eduid.vccs.client import VCCSClient, VCCSClientHTTPError, VCCSPasswordFactor, VCCSRevokeFactor

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckPasswordResult:
    """Result of a password check.

    :param success: True if authentication succeeded
    :param password: The Password credential that matched
    :param credentials_changed: True if credentials were modified (v2 upgrade or v1 revocation)
    """

    password: Password
    success: bool = False
    credentials_changed: bool = False


def get_vccs_client(vccs_url: str | None) -> VCCSClient:
    """
    Instantiate a VCCS client.

    :param vccs_url: VCCS authentication backend URL
    :return: vccs client
    """
    return VCCSClient(base_url=vccs_url)


def check_password(
    password: str,
    user: User,
    vccs_url: str | None = None,
    vccs: VCCSClient | None = None,
    upgrade_v2: bool = False,
    application: str = "",
    grace_period_days: int = 0,
) -> CheckPasswordResult | None:
    """
    Try to validate a user provided password.

    Credentials are tried in version-descending order so that v2 is preferred over v1
    when both exist.

    Returns a CheckPasswordResult on success, with credentials_changed=True if the
    user's credentials were modified (v2 upgrade or v1 revocation). The caller is
    responsible for persisting those changes via save_and_sync_user.

    :param password: plaintext password
    :param user: User object
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Optional already instantiated vccs client
    :param upgrade_v2: If True, transparently upgrade a successful v1 auth to v2
    :param application: Application name, required when upgrade_v2 is True
    :param grace_period_days: If > 0, revoke v1 passwords older than this many days after successful v2 auth

    :return: CheckPasswordResult on success, None on failure
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    # Sort by version descending so v2 credentials are tried first
    for user_password in sorted(user.credentials.filter(Password), key=lambda p: p.version, reverse=True):
        factor = VCCSPasswordFactor(password, credential_id=user_password.key, salt=user_password.salt)
        try:
            if vccs.authenticate(str(user.user_id), [factor]):
                credentials_changed = False

                # If v1 matched and upgrade is requested, create a v2 credential alongside it
                if user_password.version == 1 and upgrade_v2:
                    _has_v2 = any(p.version == 2 for p in user.credentials.filter(Password))
                    if not _has_v2:
                        if upgrade_password_to_v2(
                            user=user,
                            password=password,
                            old_credential=user_password,
                            application=application,
                            vccs=vccs,
                        ):
                            credentials_changed = True
                        else:
                            logger.warning(f"Password v2 upgrade failed for user {user}")

                # Grace period: revoke old v1 passwords if v2 auth succeeded and v1 is past cutoff
                if grace_period_days > 0 and user_password.version == 2:
                    if _revoke_expired_v1_passwords(user, grace_period_days, vccs):
                        credentials_changed = True

                return CheckPasswordResult(
                    password=user_password, success=True, credentials_changed=credentials_changed
                )
        except Exception:
            logger.exception(f"VCCS authentication for user {user} factor {factor} failed")
    return None


def _revoke_expired_v1_passwords(user: User, grace_period_days: int, vccs: VCCSClient) -> bool:
    """Revoke v1 passwords if the v2 credential was created more than grace_period_days ago.

    :return: True if any credentials were revoked (user was modified)
    """
    # Find the v2 password to determine when the upgrade happened
    v2_passwords = [p for p in user.credentials.filter(Password) if p.version == 2]
    if not v2_passwords:
        return False

    v2_created = v2_passwords[0].created_ts
    if v2_created is None:
        return False

    cutoff = v2_created + timedelta(days=grace_period_days)
    now = utc_now()
    if now < cutoff:
        return False  # still within grace period

    revoked_any = False
    for pw in list(user.credentials.filter(Password)):
        if pw.version == 1:
            try:
                factor = VCCSRevokeFactor(
                    str(pw.credential_id), "v2 upgrade grace period expired", reference="vccs_upgrade"
                )
                vccs.revoke_credentials(str(user.user_id), [factor])
                user.credentials.remove(pw.key)
                logger.info(f"Revoked v1 password {pw.credential_id} (grace period expired)")
                revoked_any = True
            except Exception:
                logger.exception(f"Failed to revoke v1 password {pw.credential_id}")
    return revoked_any


def upgrade_password_to_v2(
    user: User,
    password: str,
    old_credential: Password,
    application: str,
    vccs: VCCSClient,
) -> bool:
    """
    Create a new v2 (NDNv2) password credential alongside the existing v1 credential.

    :param user: User object
    :param password: plaintext password (available during authentication)
    :param old_credential: The existing v1 Password credential
    :param application: Application requesting the upgrade
    :param vccs: Already instantiated VCCS client

    :return: True on success, False on failure
    """
    new_credential_id = str(ObjectId())
    new_factor = VCCSPasswordFactor(password, credential_id=new_credential_id, version="NDNv2")

    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error(f"Failed adding v2 password credential {new_credential_id} for user {user}")
        return False

    logger.info(
        f"Added v2 password credential {new_credential_id} for user {user} (upgraded from {old_credential.key})"
    )

    v2_password = Password(
        credential_id=new_factor.credential_id,
        salt=new_factor.salt,
        is_generated=old_credential.is_generated,
        created_by=application,
        version=2,
    )
    user.credentials.add(v2_password)
    return True


def add_password(
    user: User,
    new_password: str,
    application: str,
    is_generated: bool = False,
    vccs_url: str | None = None,
    vccs: VCCSClient | None = None,
    version: int = 1,
) -> bool:
    """
    :param user: User object
    :param new_password: plaintext new password
    :param application: Application requesting credential change
    :param is_generated: True if this is a password generated by the eduID backend, rather than chosen by the user
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Optional already instantiated vccs client
    :param version: Password version (1 for NDNv1, 2 for NDNv2)

    :return: Success or not
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    _vccs_version = "NDNv2" if version == 2 else "NDNv1"
    new_factor = VCCSPasswordFactor(new_password, credential_id=str(ObjectId()), version=_vccs_version)

    # Add the new password
    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error(f"Failed adding password credential {new_factor.credential_id} for user {user}")
        return False  # something failed
    logger.info(f"Added password credential {new_factor.credential_id} for user {user}")

    # Add new password to user
    _password = Password(
        credential_id=new_factor.credential_id,
        salt=new_factor.salt,
        is_generated=is_generated,
        created_by=application,
        version=version,
    )
    user.credentials.add(_password)
    return True


def reset_password(
    user: User,
    new_password: str,
    application: str,
    is_generated: bool = False,
    vccs_url: str | None = None,
    vccs: VCCSClient | None = None,
    version: int = 1,
) -> bool:
    """
    :param user: User object
    :param new_password: plaintext new password
    :param application: Application requesting credential change
    :param is_generated: True if this is a password generated by the eduID backend, rather than chosen by the user
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Optional already instantiated vccs client
    :param version: Password version (1 for NDNv1, 2 for NDNv2)

    :return: Success or not
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    _vccs_version = "NDNv2" if version == 2 else "NDNv1"
    new_factor = VCCSPasswordFactor(new_password, credential_id=str(ObjectId()), version=_vccs_version)

    # Revoke all existing passwords
    if not revoke_passwords(user, "password reset", application=application, vccs=vccs):
        # TODO: Not sure if ignoring errors is the right thing to do here. Old credential might be compromised.
        logger.error(f"Failed revoking password credentials for user {user} - proceeding anyways")

    # Add the new password
    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error(f"Failed adding password credential {new_factor.credential_id} for user {user}")
        return False  # something failed
    logger.info(f"Added password credential {new_factor.credential_id} for user {user}")

    # Add new password to user
    _password = Password(
        credential_id=new_factor.credential_id,
        salt=new_factor.salt,
        is_generated=is_generated,
        created_by=application,
        version=version,
    )
    user.credentials.add(_password)
    return True


def change_password(
    user: User,
    new_password: str,
    application: str,
    old_password: str | None = None,
    old_password_id: str | None = None,
    is_generated: bool = False,
    vccs_url: str | None = None,
    vccs: VCCSClient | None = None,
    version: int = 1,
) -> bool:
    """
    :param user: User object
    :param new_password: Plaintext new password
    :param old_password: Plaintext current password
    :param old_password_id: Id for password that was used for reauthn
    :param application: Application requesting credential change
    :param is_generated: True if this is a password generated by the eduID backend, rather than chosen by the user
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Optional already instantiated vccs client
    :param version: Password version (1 for NDNv1, 2 for NDNv2)

    :return: Success or not
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    _vccs_version = "NDNv2" if version == 2 else "NDNv1"
    new_factor = VCCSPasswordFactor(new_password, credential_id=str(ObjectId()), version=_vccs_version)
    del new_password  # don't need it anymore, try to forget it

    # Check that the old password is correct, if supplied
    checked_password = None
    if old_password is not None:
        check_result = check_password(old_password, user, vccs_url=vccs_url, vccs=vccs)
        del old_password  # don't need it anymore, try to forget it
        if check_result is None or not check_result.success:
            logger.error("Old password did not match for user")
            return False
        checked_password = check_result.password

    # Revoke the old password or all current passwords as a fallback if old password or old password id is missing.
    if checked_password is not None or old_password_id is not None:
        revoke_password(
            user=user,
            reason="changing password",
            reference=application,
            old_password=checked_password,
            old_password_id=old_password_id,
            vccs_url=vccs_url,
            vccs=vccs,
        )
    else:
        # We don't know which password was used to reauthn, revoke all current passwords.
        revoke_passwords(user=user, reason="changing password", application=application, vccs_url=vccs_url, vccs=vccs)

    # Add the new password
    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error(f"Failed adding password credential {new_factor.credential_id}")
        return False  # something failed
    logger.info(f"Added password credential {new_factor.credential_id}")

    # Add new password to user
    _password = Password(
        credential_id=new_factor.credential_id,
        salt=new_factor.salt,
        is_generated=is_generated,
        created_by=application,
        version=version,
    )
    user.credentials.add(_password)
    return True


def revoke_password(
    user: User,
    reason: str,
    reference: str,
    old_password: Password | None = None,
    old_password_id: str | None = None,
    vccs_url: str | None = None,
    vccs: VCCSClient | None = None,
) -> bool:
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    credential_id = None
    credential_key = None
    if old_password is not None:
        credential_id = str(old_password.credential_id)
        credential_key = old_password.key
    elif old_password_id is not None:
        password = cast(Password, user.credentials.find(ElementKey(old_password_id)))
        if password:
            credential_id = str(password.credential_id)
            credential_key = password.key

    if credential_id is None or credential_key is None:
        return False

    # Revoke password
    vccs.revoke_credentials(
        str(user.user_id), [VCCSRevokeFactor(credential_id=credential_id, reason=reason, reference=reference)]
    )
    # Remove password from user
    user.credentials.remove(credential_key)
    logger.info(f"Revoked credential {credential_id}")
    return True


def revoke_passwords(
    user: User, reason: str, application: str, vccs_url: str | None = None, vccs: VCCSClient | None = None
) -> bool:
    """
    :param user: User object
    :param reason: Reason for revoking all passwords
    :param application: Application requesting credential change
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Optional already instantiated vccs client

    :return: Success or not
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    revoke_factors = []
    for password in user.credentials.filter(Password):
        credential_id = str(password.key)
        factor = VCCSRevokeFactor(credential_id, reason, reference=application)
        logger.debug(f'Revoking credential {credential_id} for user {user} with reason "{reason}"')
        revoke_factors.append(factor)
        user.credentials.remove(password.key)

    userid = str(user.user_id)
    try:
        vccs.revoke_credentials(userid, revoke_factors)
    except VCCSClientHTTPError:
        # One of the passwords was already revoked
        # TODO: vccs backend should be changed to return something more informative than
        # TODO: VCCSClientHTTPError when the credential is already revoked or just return success.
        logger.warning(f"VCCS failed to revoke all passwords for user {user}")
        return False
    return True
