#
# Copyright (c) 2015 NORDUnet A/S
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

from datetime import datetime
from bson import ObjectId
from eduid_userdb.dashboard import DashboardLegacyUser, DashboardUser
from eduid_userdb import Password

import vccs_client

import logging
logger = logging.getLogger(__name__)


def get_vccs_client(vccs_url):
    """
    Instantiate a VCCS client.
    :param vccs_url: VCCS authentication backend URL
    :type vccs_url: string
    :return: vccs client
    :rtype: VCCSClient
    """
    return vccs_client.VCCSClient(
        base_url=vccs_url,
    )


def check_password(vccs_url, password, user, vccs=None):
    """ Try to validate a user provided password.

    Returns False or a dict with data about the credential that validated.

    :param vccs_url: URL to VCCS authentication backend
    :param password: plaintext password
    :param user: user dict
    :param vccs: optional vccs client instance

    :type vccs_url: string
    :type password: string
    :type user: dict
    :type vccs: None or VCCSClient
    :rtype: bool or dict
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)

    # upgrade DashboardLegacyUser to DashboardUser
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser(data=user._mongo_doc)

    for cred in user.passwords.to_list():
        factor = vccs_client.VCCSPasswordFactor(
            password,
            credential_id=str(cred.id),
            salt=cred.salt,
            )
        try:
            if vccs.authenticate(str(user.user_id), [factor]):
                return cred
        except Exception as exc:
            logger.warning("VCCS authentication threw exception: {!s}".format(exc))
    return False


def add_credentials(vccs_url, old_password, new_password,
                    user, source='dashboard', vccs=None):
    """
    Add a new password to a user. Revokes the old one, if one is given.

    Returns True on success.

    :param vccs_url: URL to VCCS authentication backend
    :param old_password: plaintext current password
    :param new_password: plaintext new password
    :param user: user object

    :type vccs_url: string
    :type old_password: string
    :type user: User
    :rtype: bool
    """
    password_id = ObjectId()
    if vccs is None:
        vccs = get_vccs_client(vccs_url)
    new_factor = vccs_client.VCCSPasswordFactor(new_password,
                                                credential_id=str(password_id))

    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser(data=user._mongo_doc)

    old_factor = None
    checked_password = None
    # remember if an old password was supplied or not, without keeping it in
    # memory longer than we have to
    old_password_supplied = bool(old_password)
    if user.passwords.count > 0 and old_password:
        # Find the old credential to revoke
        checked_password = check_password(vccs_url, old_password, user, vccs=vccs)
        del old_password # don't need it anymore, try to forget it
        if not checked_password:
            return False
        old_factor = vccs_client.VCCSRevokeFactor(
            str(checked_password.id),
            'changing password',
            reference=source,
        )

    if not vccs.add_credentials(str(user.user_id), [new_factor]):
        logger.warning("Failed adding password credential "
                    "{!r} for user {!r}".format(
                        new_factor.credential_id, user))
        return False  # something failed
    logger.debug("Added password credential {!s} for user {!s}".format(
        new_factor.credential_id, user))

    if old_factor:
        vccs.revoke_credentials(str(user.user_id), [old_factor])
        user.passwords.remove(checked_password.id)
        logger.debug("Revoked old credential {!s} (user {!s})".format(
            old_factor.credential_id, user))

    if not old_password_supplied:
        # TODO: Revoke all current credentials on password reset for now
        revoked = []
        for password in user.passwords.to_list():
            revoked.append(vccs_client.VCCSRevokeFactor(str(password.id),
                                                        'reset password',
                                                        reference=source))
            logger.debug("Revoking old credential (password reset) "
                      "{!s} (user {!s})".format(
                          password.id, user))
            user.passwords.remove(password.id)
        if revoked:
            try:
                vccs.revoke_credentials(str(user.user_id), revoked)
            except vccs_client.VCCSClientHTTPError:
                # Password already revoked
                # TODO: vccs backend should be changed to return something more informative than
                # TODO: VCCSClientHTTPError when the credential is already revoked or just return success.
                logger.warning("VCCS failed to revoke all passwords for "
                            "user {!s}".format(user))

    new_password = Password(credential_id = password_id,
                            salt = new_factor.salt,
                            application = source,
                            )
    user.passwords.add(new_password)

    return user


def revoke_all_credentials(vccs_url, user, source='dashboard', vccs=None):
    if vccs is None:
        vccs = get_vccs_client(vccs_url)
    if isinstance(user, DashboardLegacyUser):
        user = DashboardUser(data=user._mongo_doc)
    to_revoke = []
    for passwd in user.passwords.to_list():
        credential_id = str(passwd.id)
        factor = vccs_client.VCCSRevokeFactor(
            credential_id,
            'subscriber requested termination',
            reference=source
        )
        logger.debug("Revoked old credential (account termination)"
                  " {!s} (user {!s})".format(
                      credential_id, user))
        to_revoke.append(factor)
    userid = str(user.user_id)
    vccs.revoke_credentials(userid, to_revoke)
