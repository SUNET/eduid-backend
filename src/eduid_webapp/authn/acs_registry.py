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
'''
Registry for actions to be performed after an IdP sends a POST
request in response to a SAML request initiated by the service

The actions are defined in the acs_actions module,
ant they are performed in the assertion consumer service view,
and are called with two positional parameters:

 * the session_info given in the SAML response (a dict)
 * The user object
'''

from flask import session

import logging
logger = logging.getLogger(__name__)


_actions = {}


def acs_action(action_key):
    '''
    Decorator to register a new assertion consumer service action.

    :param action_key: the key for the given action
    :type action_key: str
    '''
    def outer(func):
        logger.info('Registering acs action ' + action_key)
        _actions[action_key] = func

        def inner(*args, **kwargs):
            return func(*args, **kwargs)
        return inner
    return outer


def schedule_action(action_key):
    '''
    Schedule an action to be executed after an IdP responds to a SAML request.
    This is called just before the SAML request is sent.

    :param session: the session
    :type session: Session
    :param action_key: the key for the given action
    :type action_key: str
    '''
    logger.debug('Scheduling acs action ' + action_key)
    session['post-authn-action'] = action_key


def get_action():
    '''
    retrieve an action from the registry based on the key
    stored in the session.

    :param sesison: the session
    :type session: Session
    :return: the action
    :rtype: function
    '''
    try:
        action_key = session['post-authn-action']
    except KeyError:
        action_key = 'login-action'
    else:
        del session['post-authn-action']
    logger.debug('Consuming acs action ' + action_key)
    return _actions[action_key]
