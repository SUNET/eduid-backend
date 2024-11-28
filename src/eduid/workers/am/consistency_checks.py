import copy
from typing import Any

from bson import ObjectId
from celery.utils.log import get_task_logger

from eduid.userdb import LockedIdentityList
from eduid.userdb.exceptions import DocumentDoesNotExist, LockedIdentityViolation
from eduid.userdb.identity import IdentityList, IdentityType
from eduid.userdb.userdb import AmDB

__author__ = "lundberg"

logger = get_task_logger(__name__)


def unverify_duplicates(userdb: AmDB, user_id: ObjectId, attributes: dict) -> dict[str, int]:
    """
    Checks supplied attributes for keys that should have only one user with that
    element verified.

    Checks for verified mail addresses, phone numbers and identities.

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
    if attributes.get("$set"):
        mail_count = unverify_mail_aliases(userdb, user_id, attributes["$set"].get("mailAliases"))
        phone_count = unverify_phones(userdb, user_id, attributes["$set"].get("phone"))
        nin_count = unverify_identities(userdb, user_id, attributes["$set"].get("identities"))
    return {"mail_count": mail_count, "phone_count": phone_count, "nin_count": nin_count}


def unverify_mail_aliases(userdb: AmDB, user_id: ObjectId, mail_aliases: list[dict[str, Any]] | None) -> int:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param mail_aliases: sub dict of attributes

    :return: How many mailAliases that where unverified
    :rtype: int
    """
    count = 0
    if mail_aliases is None:
        logger.debug(f"No mailAliases to check duplicates against for user {user_id}.")
        return count
    # Get the verified mail addresses from attributes
    verified_mail_aliases = [alias["email"] for alias in mail_aliases if alias.get("verified") is True]
    for email in verified_mail_aliases:
        try:
            for user in userdb.get_users_by_mail(email):
                if user.user_id != user_id:
                    logger.debug(f"Removing mail address {email} from user {user}")
                    logger.debug(f"Old user mail aliases BEFORE: {user.mail_addresses.to_list()}")
                    if user.mail_addresses.primary and user.mail_addresses.primary.email == email:
                        # Promote some other verified e-mail address to primary
                        for address in user.mail_addresses.to_list():
                            if address.is_verified and address.email != email:
                                user.mail_addresses.set_primary(address.key)
                                break
                    old_user_mail_address = user.mail_addresses.find(email)
                    if old_user_mail_address is not None:
                        old_user_mail_address.is_primary = False
                        old_user_mail_address.is_verified = False
                    count += 1
                    logger.debug(f"Old user mail aliases AFTER: {user.mail_addresses.to_list()}")
                    userdb.save(user)
        except DocumentDoesNotExist:
            pass
    return count


def unverify_phones(userdb: AmDB, user_id: ObjectId, phones: list[dict[str, Any]]) -> int:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param phones: sub dict of attributes

    :return: How many phones that where unverified
    """
    count = 0
    if phones is None:
        logger.debug(f"No phones to check duplicates against for user {user_id}.")
        return count
    # Get the verified phone numbers from attributes
    verified_phone_numbers = [phone["number"] for phone in phones if phone.get("verified") is True]
    for number in verified_phone_numbers:
        try:
            for user in userdb.get_users_by_phone(number):
                if user.user_id != user_id:
                    logger.debug(f"Removing phone number {number} from user {user}")
                    logger.debug(f"Old user phone numbers BEFORE: {user.phone_numbers.to_list()}.")
                    if user.phone_numbers.primary and user.phone_numbers.primary.number == number:
                        # Promote some other verified phone number to primary
                        for phone in user.phone_numbers.verified:
                            if phone.number != number:
                                user.phone_numbers.set_primary(phone.key)
                                break
                    old_user_phone_number = user.phone_numbers.find(number)
                    if old_user_phone_number is not None:
                        old_user_phone_number.is_primary = False
                        old_user_phone_number.is_verified = False
                    count += 1
                    logger.debug(f"Old user phone numbers AFTER: {user.phone_numbers.to_list()}.")
                    userdb.save(user)
        except DocumentDoesNotExist:
            pass
    return count


def unverify_identities(userdb: AmDB, user_id: ObjectId, identities: list[dict[str, Any]]) -> int:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param identities: sub dict of attributes

    :return: How many nins that where unverified
    """
    count = 0
    if identities is None:
        logger.debug(f"No identities to check duplicates against for user {user_id!s}.")
        return count
    identity_list = IdentityList.from_list_of_dicts(identities)
    for identity in identity_list.to_list():
        if identity.is_verified is False:
            continue
        try:
            # get all users with this verified identity
            for other_user in userdb.get_users_by_identity(
                identity_type=identity.identity_type, key=identity.unique_key_name, value=identity.unique_value
            ):
                if other_user.user_id != user_id:
                    logger.debug(f"Removing identity {identity} from user {other_user.eppn}")
                    logger.debug(f"Old user identities BEFORE: {other_user.identities.to_list()}.")
                    other_identity = other_user.identities.find(identity.identity_type)
                    if other_identity is not None and other_identity.unique_value == identity.unique_value:
                        other_identity.is_verified = False
                    count += 1
                    logger.debug(f"Old user identities AFTER: {other_user.identities.to_list()}.")
                    userdb.save(other_user)
        except DocumentDoesNotExist:
            pass
    return count


def check_locked_identity(
    userdb: AmDB, user_id: ObjectId, attributes: dict, app_name: str, replace_locked: IdentityType | None = None
) -> dict:
    """
    :param userdb: Central userdb
    :param user_id: User document _id
    :param attributes: attributes to update
    :param app_name: calling application name, like 'eduid_signup'

    :return: attributes to update
    """
    # Check verified identities that will be set against the locked_identity attribute,
    # if that does not exist it should be created
    set_attributes = attributes.get("$set", {})
    identity_list = IdentityList.from_list_of_dicts(set_attributes.get("identities", []))

    # Get the users locked identities
    user = userdb.get_user_by_id(user_id)
    locked_identities = user.locked_identity if user else LockedIdentityList()
    updated = False
    for identity in identity_list.to_list():
        if identity.is_verified is False:
            # if the identity is not verified then locked identities does not matter
            continue

        locked_identity = locked_identities.find(identity.identity_type)
        # add new verified identity to locked identities
        if locked_identity is None:
            if identity.created_by is None:
                identity.created_by = app_name
            locked_identities.add(identity)
            updated = True
            continue

        if replace_locked is locked_identity.identity_type:
            # replace the locked identity with the new verified identity
            if identity.created_by is None:
                identity.created_by = app_name
            locked_identities.replace(identity)
            updated = True
            continue

        # there is already an identity of the verified identity type in locked identities
        # bail if they do not match
        if identity.unique_value != locked_identity.unique_value:
            logger.error(f"Verified identity does not match locked identity for user with id {user_id}")
            logger.debug(f"identity: {identity}")
            logger.debug(f"locked_identity: {locked_identity}")
            raise LockedIdentityViolation(f"Verified nin does not match locked identity for user with id {user_id}")

    new_attributes = copy.deepcopy(attributes)
    if updated:
        new_attributes["$set"]["locked_identity"] = locked_identities.to_list_of_dicts()

    return new_attributes
