#
# Copyright (c) 2015, 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import logging
from typing import Optional, Union

from bson import ObjectId

import vccs_client
from eduid_userdb.credentials import Password
from eduid_userdb.dashboard import DashboardLegacyUser, DashboardUser
from eduid_userdb.user import User

from eduid_common.api.decorators import deprecated

logger = logging.getLogger(__name__)


def get_vccs_client(vccs_url):
    """
    Instantiate a VCCS client.

    :param vccs_url: VCCS authentication backend URL
    :type vccs_url: string
    :return: vccs client
    :rtype: VCCSClient
    """
    return vccs_client.VCCSClient(base_url=vccs_url,)


def check_password(vccs_url, password, user, vccs=None):
    """ Try to validate a user provided password.

    Returns False or a dict with data about the credential that validated.

    :param vccs_url: URL to VCCS authentication backend
    :param password: plaintext password
    :param user: user dict
    :param vccs: optional vccs client instance

    :type vccs_url: string
    :type password: string
    :type user: User | DashboardLegacyUser
    :type vccs: None or VCCSClient
    :rtype: bool or eduid_userdb.credentials.Password
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    # upgrade DashboardLegacyUser to DashboardUser
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser.from_dict(data=user._mongo_doc)

    for user_password in user.credentials.filter(Password).to_list():
        factor = vccs_client.VCCSPasswordFactor(
            password, credential_id=str(user_password.key), salt=user_password.salt,
        )
        try:
            if vccs.authenticate(str(user.user_id), [factor]):
                return user_password
        except Exception as exc:
            logger.error("VCCS authentication threw exception: {!s}".format(exc))
    return False


def add_password(
    user: User,
    new_password: str,
    application: str,
    is_generated: bool = False,
    vccs_url: Optional[str] = None,
    vccs: Optional[vccs_client.VCCSClient] = None,
) -> Union[User, bool]:
    """
    :param user: User object
    :param new_password: plaintext new password
    :param application: Application requesting credential change
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Instantiated vccs client

    :return: User object | Boolean
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    credential_id = ObjectId()
    # TODO: Init VCCSPasswordFactor with password hash instead of plain text password
    new_factor = vccs_client.VCCSPasswordFactor(new_password, credential_id=str(credential_id))

    # Add the new password
    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error('Failed adding password credential {} for user {}'.format(new_factor.credential_id, user))
        return False  # something failed
    logger.info('Added password credential {} for user {}'.format(new_factor.credential_id, user))

    # Add new password to user
    new_password = Password(
        credential_id=credential_id, salt=new_factor.salt, is_generated=is_generated, application=application
    )
    user.credentials.add(new_password)
    return user


def reset_password(
    user: User,
    new_password: str,
    application: str,
    is_generated: bool = False,
    vccs_url: Optional[str] = None,
    vccs: Optional[vccs_client.VCCSClient] = None,
) -> Union[User, bool]:
    """
    :param user: User object
    :param new_password: plaintext new password
    :param application: Application requesting credential change
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Instantiated vccs client

    :return: User object | Boolean
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    credential_id = ObjectId()
    # TODO: Init VCCSPasswordFactor with password hash instead of plain text password
    new_factor = vccs_client.VCCSPasswordFactor(new_password, credential_id=str(credential_id))

    # Revoke all existing passwords
    user = revoke_passwords(user, 'password reset', application=application, vccs=vccs)

    # Add the new password
    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error('Failed adding password credential {} for user {}'.format(new_factor.credential_id, user))
        return False  # something failed
    logger.info('Added password credential {} for user {}'.format(new_factor.credential_id, user))

    # Add new password to user
    new_password = Password(
        credential_id=credential_id, salt=new_factor.salt, is_generated=is_generated, application=application
    )
    user.credentials.add(new_password)
    return user


def change_password(
    user: User,
    new_password: str,
    old_password: str,
    application: str,
    is_generated: bool = False,
    vccs_url: Optional[str] = None,
    vccs: Optional[vccs_client.VCCSClient] = None,
) -> Union[User, bool]:
    """
    :param user: User object
    :param new_password: plaintext new password
    :param application: Application requesting credential change
    :param old_password: Plaintext current password
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Instantiated vccs client

    :type user: User | DashboardLegacyUser
    :type new_password: six.string_types
    :type application: six.string_types
    :type old_password: six.string_types
    :type vccs_url: six.string_types
    :type vccs: vccs_client.VCCSClient

    :return: User object | Boolean
    :rtype: User | False
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    credential_id = ObjectId()
    # TODO: Init VCCSPasswordFactor with password hash instead of plain text password
    new_factor = vccs_client.VCCSPasswordFactor(new_password, credential_id=str(credential_id))
    del new_password  # don't need it anymore, try to forget it

    # Check the old password and turn it in to a RevokeFactor
    checked_password = check_password(vccs_url, old_password, user, vccs=vccs)
    del old_password  # don't need it anymore, try to forget it
    if not checked_password:
        logger.error('Old password did not match for user {}'.format(user))
        return False
    revoke_factor = vccs_client.VCCSRevokeFactor(
        str(checked_password.credential_id), 'changing password', reference=application
    )

    # Add the new password
    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.error('Failed adding password credential {} for user {}'.format(new_factor.credential_id, user))
        return False  # something failed
    logger.info('Added password credential {} for user {}'.format(new_factor.credential_id, user))

    # Revoke the old password
    vccs.revoke_credentials(str(user.user_id), [revoke_factor])
    user.credentials.remove(checked_password.credential_id)
    logger.info('Revoked credential {} for user {}'.format(revoke_factor.credential_id, user))

    # Add new password to user
    new_password = Password(
        credential_id=credential_id, salt=new_factor.salt, is_generated=is_generated, application=application
    )
    user.credentials.add(new_password)
    return user


@deprecated
def add_credentials(vccs_url, old_password, new_password, user, source='dashboard', vccs=None):
    """
    Add a new password to a user. Revokes the old one, if one is given.
    Revokes all old passwords if no old one is given - password reset.

    :param user: User object
    :param new_password: plaintext new password
    :param source: Application requesting credential change
    :param old_password: Plaintext current password
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Instantiated vccs client

    :type user: User | DashboardLegacyUser
    :type new_password: six.string_types
    :type source: six.string_types
    :type old_password: six.string_types
    :type vccs_url: six.string_types
    :type vccs: vccs_client.VCCSClient

    :return: User object | Boolean
    :rtype: User | False
    """
    # XXX: Can we remove this check?
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser.from_dict(data=user._mongo_doc)

    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    credential_id = ObjectId()
    new_factor = vccs_client.VCCSPasswordFactor(new_password, credential_id=str(credential_id))

    old_factor = None
    checked_password = None
    # remember if an old password was supplied or not, without keeping it in
    # memory longer than we have to
    old_password_supplied = bool(old_password)
    if user.credentials.filter(Password).count > 0 and old_password_supplied:
        # Find the old credential to revoke
        checked_password = check_password(vccs_url, old_password, user, vccs=vccs)
        del old_password  # don't need it anymore, try to forget it
        if not checked_password:
            return False
        old_factor = vccs_client.VCCSRevokeFactor(
            str(checked_password.credential_id), 'changing password', reference=source,
        )

    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.warning("Failed adding password credential {!r} for user {!r}".format(new_factor.credential_id, user))
        return False  # something failed
    logger.debug("Added password credential {!s} for user {!s}".format(new_factor.credential_id, user))

    if old_factor:
        vccs.revoke_credentials(str(user.user_id), [old_factor])
        user.credentials.remove(checked_password.credential_id)
        logger.debug("Revoked old credential {!s} (user {!s})".format(old_factor.credential_id, user))

    if not old_password_supplied:
        # XXX: Revoke all current credentials on password reset for now
        revoked = []
        for password in user.credentials.filter(Password).to_list():
            revoked.append(
                vccs_client.VCCSRevokeFactor(str(password.credential_id), 'reset password', reference=source)
            )
            logger.debug(
                "Revoking old credential (password reset) " "{!s} (user {!s})".format(password.credential_id, user)
            )
            user.credentials.remove(password.credential_id)
        if revoked:
            try:
                vccs.revoke_credentials(str(user.user_id), revoked)
            except vccs_client.VCCSClientHTTPError:
                # Password already revoked
                # TODO: vccs backend should be changed to return something more informative than
                # TODO: VCCSClientHTTPError when the credential is already revoked or just return success.
                logger.warning("VCCS failed to revoke all passwords for " "user {!s}".format(user))

    new_password = Password(credential_id=credential_id, salt=new_factor.salt, application=source)
    user.credentials.add(new_password)
    return user


def revoke_passwords(user, reason, application, vccs_url=None, vccs=None):
    """
    :param user: User object
    :param reason: Reason for revokin all passwords
    :param application: Application requesting credential change
    :param vccs_url: URL to VCCS authentication backend
    :param vccs: Instantiated vccs client

    :type user: User
    :type reason: six.string_types
    :type application: six.string_types
    :type vccs_url: six.string_types
    :type vccs: vccs_client.VCCSClient

    :return: User object
    :rtype: User
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    revoke_factors = []
    for password in user.credentials.filter(Password).to_list():
        credential_id = str(password.key)
        factor = vccs_client.VCCSRevokeFactor(credential_id, reason, reference=application)
        logger.debug("Revoking credential {} for user {} with reason \"{}\"".format(credential_id, user, reason))
        revoke_factors.append(factor)
        user.credentials.remove(password.key)

    userid = str(user.user_id)
    try:
        vccs.revoke_credentials(userid, revoke_factors)
    except vccs_client.VCCSClientHTTPError:
        # One of the passwords was already revoked
        # TODO: vccs backend should be changed to return something more informative than
        # TODO: VCCSClientHTTPError when the credential is already revoked or just return success.
        logger.warning('VCCS failed to revoke all passwords for user {}'.format(user))
    return user


@deprecated
def revoke_all_credentials(vccs_url, user, source='dashboard', vccs=None):
    if vccs is None:
        vccs = get_vccs_client(vccs_url)
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser.from_dict(data=user._mongo_doc)
    to_revoke = []
    for password in user.credentials.filter(Password).to_list():
        credential_id = str(password.credential_id)
        factor = vccs_client.VCCSRevokeFactor(credential_id, 'subscriber requested termination', reference=source)
        logger.debug("Revoked old credential (account termination)" " {!s} (user {!s})".format(credential_id, user))
        to_revoke.append(factor)
    userid = str(user.user_id)
    vccs.revoke_credentials(userid, to_revoke)
