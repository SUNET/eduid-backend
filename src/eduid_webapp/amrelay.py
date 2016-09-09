# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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
This file comes from eduiddashboard.amrelay
"""

from flask import current_app

from eduid_am.celery import celery
from eduid_am.tasks import update_attributes_keep_result

__author__ = 'lundberg'


class AmRelay(object):

    class TaskFailed(Exception):
        pass

    def __init__(self, settings):

        config = settings.get('DEFAULT_CELERY_CONF')
        config.update({
            'MONGO_URI': settings.get('MONGO_URI'),
        })
        celery.conf.update(config)

        self.settings = settings

    def request_sync(self, user):
        """
        Use Celery to ask eduid-am worker to propagate changes from our
        private DashboardUserDB into the central UserDB.

        :param user: User object

        :type user: DashboardUser
        :return:
        """
        user_id = str(user.user_id)

        current_app.logger.debug("Asking Attribute Manager to sync user {!s}".format(user))
        try:
            rtask = update_attributes_keep_result.delay('eduid_dashboard', user_id)
            result = rtask.get(timeout=3)
            current_app.logger.debug("Attribute Manager sync result: {!r}".format(result))
        except:
            current_app.logger.exception("Failed Attribute Manager sync request. trying again")
            try:
                rtask = update_attributes_keep_result.delay('eduid_dashboard', user_id)
                result = rtask.get(timeout=7)
                current_app.logger.debug("Attribute Manager sync result: {!r}".format(result))
                return result
            except:
                current_app.logger.exception("Failed Attribute Manager sync request retry")
                raise
