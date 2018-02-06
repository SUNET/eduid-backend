#
# Copyright (c) 2018 NORDUnet A/S
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

from datetime import datetime, timedelta

from bson.tz_util import utc

from flask import current_app, session

from eduid_common.api.utils import get_user, get_unique_hash
from eduid_userdb.dashboard import DashboardUser
from eduid_userdb import User
from eduid_userdb.nin import Nin
from eduid_userdb.mail import MailAddress
from eduid_userdb.phone import PhoneNumber
from eduid_userdb.element import DuplicateElementViolation
from eduid_userdb.exceptions import UserOutOfSync, UserDBValueError


def retrieve_modified_ts(user, dashboard_userdb):
    """
    When loading a user from the central userdb, the modified_ts has to be
    loaded from the dashboard private userdb (since it is not propagated to
    'attributes' by the eduid-am worker).

    This need should go away once there is a global version number on the user document.

    :param user: User object from the central userdb
    :param dashboard_userdb: Dashboard private userdb

    :type user: eduid_userdb.User
    :type dashboard_userdb: eduid_userdb.dashboard.DashboardUserDB

    :return: None
    """
    try:
        userid = user.user_id
    except UserDBValueError:
        current_app.logger.debug("User {!s} has no id, setting modified_ts to None".format(user))
        user.modified_ts = None
        return

    dashboard_user = dashboard_userdb.get_user_by_id(userid, raise_on_missing=False)
    if dashboard_user is None:
        current_app.logger.debug("User {!s} not found in {!s}, setting modified_ts to None".format(user, dashboard_userdb))
        user.modified_ts = None
        return

    if dashboard_user.modified_ts is None:
        dashboard_user.modified_ts = True  # use current time
        current_app.logger.debug("Updating user {!s} with new modified_ts: {!s}".format(
            dashboard_user, dashboard_user.modified_ts))
        dashboard_userdb.save(dashboard_user, check_sync = False)

    user.modified_ts = dashboard_user.modified_ts
    current_app.logger.debug("Updating {!s} with modified_ts from dashboard user {!s}: {!s}".format(
        user, dashboard_user, dashboard_user.modified_ts))

def save_dashboard_user(user):
    """
    Save (new) user objects to the dashboard db in the new format,
    and propagate the changes to the central user db.

    May raise UserOutOfSync exception

    :param user: the modified user
    :type user: eduid_userdb.dashboard.user.DashboardUser
    """
    if isinstance(user, User):
        # turn it into a DashboardUser before saving it in the dashboard private db
        user = DashboardUser(data = user.to_dict())
    current_app.old_dashboard_userdb.save(user, old_format=False)
    current_app.logger.debug('Root factory propagate_user_changes')
    return current_app.am_relay.request_sync(user)

def dummy_message(message):
    """
    This function is only for debugging purposes
    """
    current_app.logger.debug('[DUMMY_MESSAGE]: {!s}'.format(message))


def get_verification_code(model_name, obj_id=None, code=None, user=None):
    """
    Match a user supplied code (`code') against an actual entry in the database.

    :param request: The HTTP request
    :param model_name: 'norEduPersonNIN', 'phone', or 'mailAliases'
    :param obj_id: The data covered by the verification, like the phone number or nin or ...
    :param code: User supplied code
    :param user: The user

    :type request: pyramid.request.Request
    :type model_name: str | unicode
    :type obj_id: str | unicode
    :type code: str | unicode
    :type user: User | OldUser

    :returns: Verification entry from the database
    :rtype: dict
    """
    assert model_name in ['norEduPersonNIN', 'phone', 'mailAliases']

    userid = None
    if user is not None:
        try:
            userid = user.user_id
        except AttributeError:
            userid = user.get_id()

    filters = {
        'model_name': model_name,
    }
    if obj_id is not None:
        filters['obj_id'] = obj_id
    if code is not None:
        filters['code'] = code
    if userid is not None:
        filters['user_oid'] = userid
    current_app.logger.debug("Verification code lookup filters : {!r}".format(filters))
    result = current_app.old_dashboard_db.verifications.find_one(filters)
    if result:
        expiration_timeout = current_app.config.get('verification_code_timeout')
        expire_limit = datetime.now(utc) - timedelta(minutes=int(expiration_timeout))
        result['expired'] = result['timestamp'] < expire_limit
        current_app.logger.debug("Verification lookup result : {!r}".format(result))
    return result


def new_verification_code(model_name, obj_id, user, hasher=None):
    """
    Match a user supplied code (`code') against an actual entry in the database.

    :param request: The HTTP request
    :param model_name: 'norEduPersonNIN', 'phone', or 'mailAliases'
    :param obj_id: The data covered by the verification, like the phone number or nin or ...
    :param user: The user
    :param hasher: Callable used to generate the code

    :type request: pyramid.request.Request
    :type model_name: str | unicode
    :type obj_id: str | unicode
    :type user: User | OldUser
    :type hasher: callable
    """
    assert model_name in ['norEduPersonNIN', 'phone', 'mailAliases']

    try:
        userid = user.user_id
    except AttributeError:
        userid = user.get_id()

    if hasher is None:
        hasher = get_unique_hash
    code = hasher()
    obj = {
        'model_name': model_name,
        'obj_id': obj_id,
        'user_oid': userid,
        'code': code,
        'verified': False,
        'timestamp': datetime.now(utc),
    }
    doc_id = current_app.old_dashboard_db.verifications.insert(obj)
    reference = unicode(doc_id)
    session_verifications = session.get('verifications', [])
    session_verifications.append(code)
    session['verifications'] = session_verifications
    current_app.logger.info('Created new {!s} verification code for user {!r}.'.format(model_name, user))
    current_app.logger.debug('Verification object id {!s}. Code: {!s}.'.format(obj_id, code))
    return reference, code


def set_phone_verified(user, new_number):
    """
    Mark a phone number as verified on a user.

    This process also includes *removing* the phone number from any other user
    that had it as a verified phone number.

    :param request: The HTTP request
    :param user: The user
    :param new_number: The phone number to mark as verified

    :type request: pyramid.request.Request
    :type user: User
    :type new_number: str | unicode

    :return: Status message
    :rtype: str | unicode
    """
    current_app.logger.info('Trying to verify phone number for user {!r}.'.format(user))
    current_app.logger.debug('Phone number: {!s}.'.format(new_number))
    # Start by removing mobile number from any other user
    old_user = current_app.central_userdb.get_user_by_phone(new_number,
            raise_on_missing=False)
    steal_count = 0
    if old_user and old_user.user_id != user.user_id:
        retrieve_modified_ts(old_user, current_app.old_dashboard_userdb)
        _remove_phone_from_user(new_number, old_user)
        save_dashboard_user(old_user)  # XXX think about attr fetcher in am relay
        current_app.logger.info('Removed phone number from user {!r}.'.format(old_user))
        steal_count = 1
    # Add the verified mobile number to the requesting user
    _add_phone_to_user(new_number, user)
    current_app.logger.info('Phone number verified for user {!r}.'.format(user))
    current_app.stats.count('verify_mobile_stolen', steal_count)
    current_app.stats.count('verify_mobile_completed')


def _remove_phone_from_user(number, user):
    """
    Remove a phone number from one user because it is being verified by another user.
    Part of set_phone_verified() above.
    """
    current_app.logger.debug('Found old user {!r} with phone number ({!s}) already verified.'.format(user, number))
    current_app.logger.debug('Old user phone numbers BEFORE: {!r}.'.format(user.phone_numbers.to_list()))
    if user.phone_numbers.primary.number == number:
        # Promote some other verified phone number to primary
        for phone in user.phone_numbers.verified.to_list():
            if phone.number != number:
                user.phone_numbers.primary = phone.number
                break
    user.phone_numbers.remove(number)
    current_app.logger.debug('Old user phone numbers AFTER: {!r}.'.format(user.phone_numbers.to_list()))
    return user


def _add_phone_to_user(new_number, user):
    """
    Add a phone number to a user.
    Part of set_phone_verified() above.
    """
    phone = PhoneNumber(data={'number': new_number,
                              'verified': True,
                              'primary': False})
    current_app.logger.debug('User had phones BEFORE verification: {!r}'.format(user.phone_numbers.to_list()))
    if user.phone_numbers.primary is None:
        current_app.logger.debug('Setting NEW phone number to primary: {}.'.format(phone))
        phone.is_primary = True
    try:
        user.phone_numbers.add(phone)
    except DuplicateElementViolation:
        user.phone_numbers.find(new_number).is_verified = True


def set_email_verified(user, new_mail):
    """
    Mark an e-mail address as verified on a user.

    This process also includes *removing* the e-mail address from any other user
    that had it as a verified e-mail address.

    :param request: The HTTP request
    :param user: The user
    :param new_mail: The e-mail address to mark as verified

    :type request: pyramid.request.Request
    :type user: User
    :type new_mail: str | unicode

    :return: Status message
    :rtype: str | unicode
    """
    current_app.logger.info('Trying to verify mail address for user {!r}.'.format(user))
    current_app.logger.debug('Mail address: {!s}.'.format(new_mail))
    # Start by removing the email address from any other user that currently has it (verified)
    old_user = current_app.central_userdb.get_user_by_mail(new_mail, raise_on_missing=False)
    steal_count = 0
    if old_user and old_user.user_id != user.user_id:
        retrieve_modified_ts(old_user, current_app.old_dashboard_userdb)
        old_user = _remove_mail_from_user(new_mail, old_user)
        save_dashboard_user(old_user)
        steal_count = 1
    # Add the verified mail address to the requesting user
    _add_mail_to_user(new_mail, user)
    current_app.logger.info('Mail address verified for user {!r}.'.format(user))
    current_app.stats.count('verify_mail_stolen', steal_count)
    current_app.stats.count('verify_mail_completed')


def _remove_mail_from_user(email, user):
    """
    Remove an email address from one user because it is being verified by another user.
    Part of set_email_verified() above.
    """
    current_app.logger.debug('Removing mail address {!s} from user {!s}'.format(email, user))
    if user.mail_addresses.primary:
        # only in the test suite could primary ever be None here
        current_app.logger.debug('Old user mail BEFORE: {!s}'.format(user.mail_addresses.primary))
    current_app.logger.debug('Old user mail aliases BEFORE: {!r}'.format(user.mail_addresses.to_list()))
    if user.mail_addresses.primary and user.mail_addresses.primary.email == email:
        # Promote some other verified e-mail address to primary
        for address in user.mail_addresses.to_list():
            if address.is_verified and address.email != email:
                user.mail_addresses.primary = address.email
                break
    user.mail_addresses.remove(email)
    if user.mail_addresses.primary is not None:
        current_app.logger.debug('Old user mail AFTER: {!s}.'.format(user.mail_addresses.primary))
    if user.mail_addresses.count > 0:
        current_app.logger.debug('Old user mail aliases AFTER: {!r}.'.format(user.mail_addresses.to_list()))
    else:
        current_app.logger.debug('Old user has NO mail AFTER.')
    return user


def _add_mail_to_user(email, user):
    """
    Add an email address to a user.
    Part of set_email_verified() above.
    """
    new_email = MailAddress(email = email, application = 'dashboard',
                            verified = True, primary = False)
    if user.mail_addresses.primary is None:
        new_email.is_primary = True
    try:
        user.mail_addresses.add(new_email)
    except DuplicateElementViolation:
        user.mail_addresses.find(email).is_verified = True


def verify_code(model_name, code):
    """
    Verify a code and act accordingly to the model_name ('norEduPersonNIN', 'phone', or 'mailAliases').

    This is what turns an unconfirmed NIN/mobile/e-mail into a confirmed one.

    :param request: The HTTP request
    :param model_name: 'norEduPersonNIN', 'phone', or 'mailAliases'
    :param code: The user supplied code
    :type request: pyramid.request.Request
    :return: string of verified data
    """
    assert model_name in ['norEduPersonNIN', 'phone', 'mailAliases']

    this_verification = current_app.old_dashboard_db.verifications.find_one(
        {
            "model_name": model_name,
            "code": code,
        })

    if not this_verification:
        current_app.logger.error("Could not find verification record for code {!r}, model {!r}".format(code, model_name))
        return

    reference = unicode(this_verification['_id'])
    obj_id = this_verification['obj_id']

    if not obj_id:
        return None

    user = get_user()
    retrieve_modified_ts(user, current_app.old_dashboard_userdb)

    assert_error_msg = 'Requesting users ID does not match verifications user ID'
    assert user.user_id == this_verification['user_oid'], assert_error_msg

    elif model_name == 'phone':
        set_phone_verified(user, obj_id)
    elif model_name == 'mailAliases':
        set_email_verified(user, obj_id)
    else:
        raise NotImplementedError('Unknown validation model_name: {!r}'.format(model_name))

    try:
        save_dashboard_user(user)
        current_app.logger.info("Verified {!s} saved for user {!r}.".format(model_name, user))
        verified = {
            'verified': True,
            'verified_timestamp': datetime.utcnow()
        }
        this_verification.update(verified)
        current_app.old_dashboard_db.verifications.update({'_id': this_verification['_id']}, this_verification)
        current_app.logger.info("Code {!r} ({!s}) marked as verified".format(code, obj_id))
    except UserOutOfSync:
        current_app.logger.info("Verified {!s} NOT saved for user {!r}. User out of sync.".format(model_name, user))
        raise
    else:
        current_app.stats.count('verify_code_completed')
    return obj_id


def save_as_verified(model_name, user, obj_id):
    """
    Update a verification code entry in the database, indicating it has been
    (successfully) used.

    :param request: The HTTP request
    :param model_name: 'norEduPersonNIN', 'phone', or 'mailAliases'
    :param user: The user
    :param obj_id: The data covered by the verification, like the phone number or nin or ...

    :type request: pyramid.request.Request
    :type model_name: str | unicode
    :type user: User | OldUser
    :type obj_id: str | unicode
    """
    try:
        userid = user.user_id
    except AttributeError:
        userid = user.get_id()

    assert model_name in ['norEduPersonNIN', 'phone', 'mailAliases']

    old_verified = current_app.old_dashboard_db.verifications.find(
        {
            "model_name": model_name,
            "verified": True,
            "obj_id": obj_id,
        })

    for old in old_verified:
        if old['user_oid'] == userid:
            return obj_id
    # User was not verified before, create a verification document
    result = current_app.old_dashboard_db.verifications.find_and_modify(
        {
            "model_name": model_name,
            "user_oid": userid,
            "obj_id": obj_id,
        }, {
            "$set": {
                "verified": True,
                "timestamp": datetime.utcnow(),
            }
        },
        upsert=True,
        new=True
    )
    return result['obj_id']


def generate_verification_link(code, model):  # XXX XXX
    link = current_app.safe_route_url("verifications", model=model, code=code)
    return link
