# -*- coding: utf-8 -*-
from __future__ import absolute_import

from typing import Any, Dict, List, Optional

from bson import ObjectId
from celery.utils.log import get_task_logger

from eduid.userdb.exceptions import DocumentDoesNotExist, LockedIdentityViolation, UserDBValueError
from eduid.userdb.locked_identity import LockedIdentityList, LockedIdentityNin
from eduid.userdb.userdb import UserDB

__author__ = 'lundberg'

logger = get_task_logger(__name__)


def unverify_duplicates(userdb, user_id, attributes):
    """
    Checks supplied attributes for keys that should have only one user with that
    element verified.

    Checks for verified mail addresses, phone numbers and nins.

    :param userdb: Central userdb
    :param user_id: User document _id
    :param attributes: attributes to update

    :type userdb: eduid.userdb.userdb.UserDB
    :type user_id: bson.ObjectId
    :type attributes: dict

    :return: How many elements where unverified (for stats)
    :rtype: dict
    """
    # We are only interested if there are any attributes to set
    mail_count, phone_count, nin_count = 0, 0, 0
    if attributes.get('$set'):
        mail_count = unverify_mail_aliases(userdb, user_id, attributes['$set'].get('mailAliases'))
        phone_count = unverify_phones(userdb, user_id, attributes['$set'].get('phone'))
        nin_count = unverify_nins(userdb, user_id, attributes['$set'].get('nins'))
    return {'mail_count': mail_count, 'phone_count': phone_count, 'nin_count': nin_count}


def unverify_mail_aliases(userdb, user_id, mail_aliases):
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param mail_aliases: sub dict of attributes


    :type userdb: eduid.userdb.userdb.UserDB
    :type user_id: bson.ObjectId
    :type mail_aliases: dict

    :return: How many mailAliases that where unverified
    :rtype: int
    """
    count = 0
    if mail_aliases is None:
        logger.debug('No mailAliases to check duplicates against for user {}.'.format(user_id))
        return None
    # Get the verified mail addresses from attributes
    verified_mail_aliases = [alias['email'] for alias in mail_aliases if alias.get('verified') is True]
    for email in verified_mail_aliases:
        try:
            for user in userdb.get_users_by_mail(email):
                if user.user_id != user_id:
                    logger.debug('Removing mail address {} from user {}'.format(email, user))
                    logger.debug('Old user mail aliases BEFORE: {}'.format(user.mail_addresses.to_list()))
                    if user.mail_addresses.primary.email == email:
                        # Promote some other verified e-mail address to primary
                        for address in user.mail_addresses.to_list():
                            if address.is_verified and address.email != email:
                                user.mail_addresses.set_primary(address.email)
                                break
                    user.mail_addresses.find(email).is_primary = False
                    user.mail_addresses.find(email).is_verified = False
                    count += 1
                    logger.debug('Old user mail aliases AFTER: {}'.format(user.mail_addresses.to_list()))
                    userdb.save(user)
        except DocumentDoesNotExist:
            pass
    return count


def unverify_phones(userdb: UserDB, user_id: ObjectId, phones: List[Dict[str, Any]]) -> Optional[int]:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param phones: sub dict of attributes

    :return: How many phones that where unverified
    """
    count = 0
    if phones is None:
        logger.debug('No phones to check duplicates against for user {}.'.format(user_id))
        return None
    # Get the verified phone numbers from attributes
    verified_phone_numbers = [phone['number'] for phone in phones if phone.get('verified') is True]
    for number in verified_phone_numbers:
        try:
            for user in userdb.get_users_by_phone(number):
                if user.user_id != user_id:
                    logger.debug('Removing phone number {} from user {}'.format(number, user))
                    logger.debug('Old user phone numbers BEFORE: {}.'.format(user.phone_numbers.to_list()))
                    if user.phone_numbers.primary.number == number:
                        # Promote some other verified phone number to primary
                        for phone in user.phone_numbers.verified:
                            if phone.number != number:
                                user.phone_numbers.set_primary(phone.number)
                                break
                    user.phone_numbers.find(number).is_primary = False
                    user.phone_numbers.find(number).is_verified = False
                    count += 1
                    logger.debug('Old user phone numbers AFTER: {}.'.format(user.phone_numbers.to_list()))
                    userdb.save(user)
        except DocumentDoesNotExist:
            pass
    return count


def unverify_nins(userdb: UserDB, user_id: ObjectId, nins: List[Dict[str, Any]]) -> Optional[int]:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param nins: sub dict of attributes

    :return: How many nins that where unverified
    """
    count = 0
    if nins is None:
        logger.debug('No nins to check duplicates against for user {!s}.'.format(user_id))
        return None
    # Get verified nins from attributes
    verified_nins = [nin['number'] for nin in nins if nin.get('verified') is True]
    for number in verified_nins:
        try:
            for user in userdb.get_users_by_nin(number):
                if user.user_id != user_id:
                    logger.debug('Removing nin {} from user {}'.format(number, user))
                    logger.debug('Old user NINs BEFORE: {}.'.format(user.nins.to_list()))
                    if user.nins.primary.number == number:
                        # Promote some other verified nin to primary (future proofing)
                        old_nins = user.nins.verified
                        for this in old_nins:
                            if this.number != number:
                                user.nins.set_primary(this.number)
                                break
                    user.nins.find(number).is_primary = False
                    user.nins.find(number).is_verified = False
                    count += 1
                    logger.debug('Old user NINs AFTER: {}.'.format(user.nins.to_list()))
                    userdb.save(user)
        except DocumentDoesNotExist:
            pass
    return count


def check_locked_identity(userdb: UserDB, user_id: ObjectId, attributes: Dict, app_name: str) -> Dict:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param attributes: attributes to update
    :param app_name: calling application name, like 'eduid_signup'

    :return: attributes to update
    """
    # Check verified nins that will be set against the locked_identity attribute,
    # if that does not exist it should be created
    set_attributes = attributes.get('$set', {})
    nins = set_attributes.get('nins', [])
    verified_nins = [nin for nin in nins if nin.get('verified') is True]
    if not verified_nins:
        return attributes  # No verified nins will be set

    # A user can not have more than one verified nin at this time
    if len(verified_nins) > 1:
        logger.error('Tried to set more than one verified nin for user with id {}'.format(user_id))
        raise UserDBValueError('Tried to set more than one verified nin for user.')

    nin = verified_nins[0]

    # Get the users locked identities
    user = userdb.get_user_by_id(user_id, raise_on_missing=False)
    locked_identities = user.locked_identity if user else LockedIdentityList()

    locked_nin = locked_identities.find('nin')
    # Create a new locked nin if it does not already exist
    if not locked_nin:
        locked_nin = LockedIdentityNin(
            number=nin['number'], created_by=nin.get('created_by', app_name), created_ts=nin.get('created_ts', True)
        )
        locked_identities.add(locked_nin)

    # Check nin to be set against locked nin
    if nin['number'] != locked_nin.number:
        logger.error(f'Verified nin does not match locked identity for user with id {user_id}')
        raise LockedIdentityViolation(f'Verified nin does not match locked identity for user with id {user_id}')

    attributes['$set']['locked_identity'] = locked_identities.to_list_of_dicts()
    return attributes
