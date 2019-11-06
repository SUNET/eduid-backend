# -*- coding: utf-8 -*-
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
from __future__ import absolute_import

from flask import abort
from eduid_common.session import session
from eduid_webapp.actions.app import current_actions_app as current_app


def get_next_action(user):
    idp_session = session.actions.session
    action = current_app.actions_db.get_next_action(user.eppn, idp_session)
    if action is None:
        current_app.logger.info("Finished pre-login actions "
                                "for user: {}".format(user))
        idp_url = '{}?key={}'.format(current_app.config.idp_url,
                                     idp_session)
        return {'action': False, 'idp_url': idp_url}

    if action.action_type not in current_app.plugins:
        current_app.logger.info("Missing plugin for action "
                                "{}".format(action.action_type))
        abort(500)

    action_dict = action.to_dict()
    action_dict['_id'] = str(action_dict['_id'])
    if 'user_oid' in action_dict:
        action_dict['user_oid'] = str(action_dict['user_oid'])
    session['current_action'] = action_dict
    session['current_step'] = 1
    session['current_plugin'] = action.action_type
    plugin_obj = current_app.plugins[action.action_type]()
    session['total_steps'] = plugin_obj.get_number_of_steps()
    return {'action': True}
