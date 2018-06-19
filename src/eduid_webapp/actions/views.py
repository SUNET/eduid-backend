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
from __future__ import absolute_import

from flask import Blueprint, request, session, current_app

from eduid_common.api.decorators import MarshalWith, UnmarshalWith
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_webapp.authn.helpers import verify_auth_token
from eduid_webapp.actions.schemas import AuthnSchema
from eduid_webapp.actions.helpers import get_next_action

actions_views = Blueprint('actions', __name__, url_prefix='')


@actions_views.route('/', methods=['GET'])
@UnmarshalWith(AuthnSchema)
@MarshalWith(FluxStandardAction)
def actions(userid, token, nonce, timestamp, idp_session):
    '''
    '''
    if not (userid and token and nonce and timestamp):
        msg = ('Insufficient authentication params: '
               'userid: {}, token: {}, nonce: {}, ts: {}')
        current_app.logger.debug(msg.format(userid, token, nonce, timestamp))
        return {
                '_status': 'error',
                'message': 'actions.authn-missing'
        }

    if verify_auth_token(eppn=userid, token=token,
                         nonce=nonce, timestamp=timestamp):
        current_app.logger.info("Starting pre-login actions "
                                "for userid: {})".format(userid))
        session['userid'] = userid
        session['idp_session'] = idp_session
        session.persist()
        return {
            'message': 'actions.authn-success'
        }
    else:
        current_app.logger.debug("Token authentication failed "
                                 "(userid: {})".format(userid))
        return {
                '_status': 'error',
                'message': 'actions.authn-error'
        }

def get():
    get_next_action()
    action_type = session['current_plugin']
    plugin_obj = current_app.plugins[action_type]()
    action = Action(data=session['current_action'])
    current_app.logger.info('Starting pre-login action {} '
                            'for userid {}'.format(action.action_type,
                                                    session['userid']))
    try:
        template, data = plugin_obj.get_action_body_for_step(1, action)
        if template is not None:
            return render_to_response(template, data)
        html = data
    except plugin_obj.ActionError as exc:
        self._aborted(action, exc)
        html = u'<div class="jumbotron"><p>{}</p></div>'
        html = html.format(exc.args[0])
    return render_to_response('main.jinja2',
                              {'plugin_html': html},
                              request=self.request)


def _aborted(action, exc):
    current_app.logger.info(u'Aborted pre-login action {} for userid {}, '
                            u'reason: {}'.format(action.action_type,
                                                 session['userid'],
                                                 exc.args[0]))
    if exc.remove_action:
        aid = action.action_id
        msg = 'Removing faulty action with id '
        current_app.logger.info(msg + str(aid))
        current_app.actions_db.remove_action_by_id(aid)
