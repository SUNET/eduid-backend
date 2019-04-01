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

__author__ = 'eperez'

import pymongo.errors
from eduid_userdb.exceptions import UserDoesNotExist
from eduid_userdb.actions.tou import ToUUserDB

import logging
logger = logging.getLogger(__name__)


class ToUAMPContext(object):
    """
    Private data for this AM plugin.
    """

    def __init__(self, db_uri):
        self.tou_userdb = None
        if db_uri is not None:
            self.tou_userdb = ToUUserDB(db_uri)


def plugin_init(am_conf):
    """
    Create a private context for this plugin.

    Whatever is returned by this function will get passed to attribute_fetcher() as
    the `context' argument.

    :param am_conf: Attribute Manager configuration data.

    :type am_conf: dict

    :rtype: ToUAMPContext
    """
    return ToUAMPContext(am_conf['MONGO_URI'])


def attribute_fetcher(context, user_id):
    """
    Read a user from the Signup private userdb and return an update
    dict to let the Attribute Manager update the use in the central
    eduid user database.

    :param context: Plugin context, see plugin_init above.
    :param user_id: Unique identifier

    :type context: ToUAMPContext
    :type user_id: ObjectId

    :return: update dict
    :rtype: dict
    """
    user = context.tou_userdb.get_user_by_id(user_id)
    if user is None:
        raise UserDoesNotExist("No user matching _id='%s'" % user_id)

    tous = user.tou.to_list_of_dicts()

    import pprint
    logger.debug("Processing user {}:\nToUs: {!r}".format(user,
        pprint.pformat(tous)))

    attributes = {'$set': {'tou': tous}}

    try:
        context.tou_userdb.remove_user_by_id(user_id)
    except pymongo.errors.OperationFailure:
        # eduid_am might not have write permission to the signup application's
        # collection. Just ignore cleanup if that is the case, and let that be
        # handled by some other process (cron job maybe).
        pass

    return attributes
