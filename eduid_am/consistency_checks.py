# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from eduid_userdb.exceptions import DocumentDoesNotExist

__author__ = 'lundberg'

logger = get_task_logger(__name__)


def unverify_duplicates(userdb, user_id, attributes):
    """
    Checks supplied attributes for keys that should have only one user with that
    element verified.

    Checks for verified mail addresses, phone numbers and nins.

    :param userdb: Central userdb
    :type userdb: eduid_userdb.userdb.UserDB
    :param user_id: User document _id
    :type user_id: bson.ObjectId
    :param attributes: attributes to update
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
    return {
        'mail_count': mail_count,
        'phone_count': phone_count,
        'nin_count': nin_count
    }


def unverify_mail_aliases(userdb, user_id, mail_aliases):
    """
    :param userdb: Central userdb
    :type userdb: eduid_userdb.userdb.UserDB
    :param user_id: User document _id
    :type user_id: bson.ObjectId
    :param mail_aliases: sub dict of attributes
    :type mail_aliases: dict
    :return: How many mailAliases that where unverified
    :rtype: int
    """
    count = 0
    if mail_aliases is None:
        logger.debug('No mailAliases to check duplicates against for user {}.'.format(user_id))
        return None
    # Get the verified mail addresses from attributes
    verified_mail_aliases = [alias['email'] for alias in mail_aliases if alias.get('verified')]
    try:
        for email in verified_mail_aliases:
            for user in userdb.get_user_by_mail(email, return_list=True):
                if user.user_id != user_id:
                    logger.debug('Removing mail address {} from user {}'.format(email, user))
                    logger.debug('Old user mail aliases BEFORE: {}'.format(user.mail_addresses.to_list()))
                    if user.mail_addresses.primary.email == email:
                        # Promote some other verified e-mail address to primary
                        for address in user.mail_addresses.to_list():
                            if address.is_verified and address.email != email:
                                user.mail_addresses.primary = address.email
                                break
                    user.mail_addresses.find(email).is_primary = False
                    user.mail_addresses.find(email).is_verified = False
                    count += 1
                    logger.debug('Old user mail aliases AFTER: {}'.format(user.mail_addresses.to_list()))
                    userdb.save(user)
    except DocumentDoesNotExist:
        pass
    return count


def unverify_phones(userdb, user_id, phones):
    """
    :param userdb: Central userdb
    :type userdb: eduid_userdb.userdb.UserDB
    :param user_id: User document _id
    :type user_id: bson.ObjectId
    :param phones: sub dict of attributes
    :type phones: dict
    :return: How many phones that where unverified
    :rtype: int
    """
    count = 0
    if phones is None:
        logger.debug('No phones to check duplicates against for user {}.'.format(user_id))
        return None
    # Get the verified phone numbers from attributes
    verified_phone_numbers = [phone['number'] for phone in phones if phone.get('verified')]
    try:
        for number in verified_phone_numbers:
            for user in userdb.get_user_by_phone(number, return_list=True):
                if user.user_id != user_id:
                    logger.debug('Removing phone number {} from user {}'.format(number, user))
                    logger.debug('Old user phone numbers BEFORE: {}.'.format(user.phone_numbers.to_list()))
                    if user.phone_numbers.primary.number == number:
                        # Promote some other verified phone number to primary
                        for phone in user.phone_numbers.verified.to_list():
                            if phone.number != number:
                                user.phone_numbers.primary = phone.number
                                break
                    user.phone_numbers.find(number).is_primary = False
                    user.phone_numbers.find(number).is_verified = False
                    count += 1
                    logger.debug('Old user phone numbers AFTER: {}.'.format(user.phone_numbers.to_list()))
                    userdb.save(user)
    except DocumentDoesNotExist:
        pass
    return count


def unverify_nins(userdb, user_id, nins):
    """
    :param userdb: Central userdb
    :type userdb: eduid_userdb.userdb.UserDB
    :param user_id: User document _id
    :type user_id: bson.ObjectId
    :param nins: sub dict of attributes
    :type nins: dict
    :return: How many nins that where unverified
    :rtype: int
    """
    count = 0
    if nins is None:
        logger.debug('No nins to check duplicates against for user {!s}.'.format(user_id))
        return None
    # Get verified nins from attributes
    verified_nins = [nin['number'] for nin in nins if nin.get('verified')]
    try:
        for number in verified_nins:
            for user in userdb.get_user_by_nin(number, return_list=True):
                if user.user_id != user_id:
                    logger.debug('Removing nin {} from user {}'.format(number, user))
                    logger.debug('Old user NINs BEFORE: {}.'.format(user.nins.to_list()))
                    if user.nins.primary.number == nin:
                        # Promote some other verified nin to primary (future proofing)
                        old_nins = user.nins.verified.to_list()
                        for this in old_nins:
                            if this.number != nin:
                                user.nins.primary = this.number
                                break
                    user.nins.find(number).is_primary = False
                    user.nins.find(number).is_verified = False
                    count += 1
                    logger.debug('Old user NINs AFTER: {}.'.format(user.nins.to_list()))
                    userdb.save(user)
    except DocumentDoesNotExist:
        pass
    return count
