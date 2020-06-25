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

from datetime import datetime

from bson import ObjectId
from flask import request

from eduid_userdb.actions import Action
from eduid_userdb.actions.tou import ToUUser, ToUUserDB
from eduid_userdb.tou import ToUEvent

from eduid_webapp.actions.action_abc import ActionPlugin
from eduid_webapp.actions.app import current_actions_app as current_app
from eduid_webapp.actions.helpers import ActionsMsg


class Plugin(ActionPlugin):

    PLUGIN_NAME = 'tou'
    PACKAGE_NAME = 'eduid_webapp.actions.actions.tou'
    steps = 1

    def __init__(self):
        super(Plugin, self).__init__()

        # This import has to happen _after_ eduid_am has been initialized
        from eduid_am.tasks import update_attributes_keep_result

        self._update_attributes = update_attributes_keep_result

    @classmethod
    def includeme(cls, app):
        app.tou_db = ToUUserDB(app.config.mongo_uri)

    def get_config_for_bundle(self, action: Action):
        tous = current_app.get_tous(version=action.params['version'])
        if not tous:
            current_app.logger.error('Could not load any TOUs')
            raise self.ActionError(ActionsMsg.no_tou)
        return {
            'version': action.params['version'],
            'tous': tous,
            'available_languages': current_app.config.available_languages,
        }

    def perform_step(self, action: Action):
        if not request.get_json().get('accept', ''):
            raise self.ActionError(ActionsMsg.must_accept)

        eppn = action.eppn
        central_user = current_app.central_userdb.get_user_by_eppn(eppn)
        user = ToUUser.from_user(central_user, current_app.tou_db)
        current_app.logger.debug('Loaded ToUUser {} from db'.format(user))

        version = action.params['version']

        existing_tou = user.tou.find(version)
        if existing_tou:
            current_app.logger.info('ToU version {} reaccepted by user {}'.format(version, user))
            existing_tou.modified_ts = datetime.utcnow()
        else:
            current_app.logger.info('ToU version {} accepted by user {}'.format(version, user))
            user.tou.add(
                ToUEvent.from_dict(
                    dict(
                        version=version,
                        created_by='eduid_tou_plugin',
                        created_ts=datetime.utcnow(),
                        modified_ts=datetime.utcnow(),
                        event_id=ObjectId(),
                    )
                )
            )

        current_app.tou_db.save(user, check_sync=False)
        current_app.logger.debug("Asking for sync of {} by Attribute Manager".format(user))
        rtask = self._update_attributes.delay('eduid_tou', str(user.user_id))
        try:
            result = rtask.get(timeout=10)
            current_app.logger.debug("Attribute Manager sync result: {!r}".format(result))
            current_app.actions_db.remove_action_by_id(action.action_id)
            current_app.logger.info('Removed completed action {}'.format(action))
            return {}
        except Exception as e:
            current_app.logger.error("Failed Attribute Manager sync request: " + str(e))
            raise self.ActionError(ActionsMsg.sync_problem)
