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
"""
# XXX remove when dumping old dashboard
"""

from datetime import datetime, timedelta
from bson.tz_util import utc

from flask import current_app


def get_old_verification_code(model_name, obj_id=None, code=None, user=None):
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
    assert model_name in ['phone', 'mailAliases']

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
        conf_var = 'EMAIL_VERIFICATION_TIMEOUT'
        if model_name == 'phone':
            conf_var = 'PHONE_VERIFICATION_TIMEOUT'
        expiration_timeout = current_app.config.get(conf_var)
        expire_limit = datetime.now(utc) - timedelta(hours=int(expiration_timeout))
        result['expired'] = result['timestamp'] < expire_limit
        current_app.logger.debug("Verification lookup result : {!r}".format(result))
    return result
