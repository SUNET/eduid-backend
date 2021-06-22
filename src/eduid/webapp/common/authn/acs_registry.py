#
# Copyright (c) 2018 SUNET
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
Registry for actions to be performed after an IdP sends a POST
request in response to a SAML request initiated by the service

The actions are defined in the acs_actions module,
and they are performed in the assertion consumer service view,
and are called with two positional parameters:

 * the session_info given in the SAML response (a dict)
 * The user object
"""
from enum import Enum
from typing import Callable, Dict, Optional

from flask import current_app

from eduid.webapp.common.session.namespaces import SP_AuthnRequest, SPAuthnData

# This is the list of ACS actions loaded. It is populated by decorating functions with the @acs_action.
# The keys are the AcsAction (subclass) enum values, since get_action() doesn't know which subclass of
# AcsActions that could be used to turn the string value stored in the session back into an Enum.
_actions: Dict[str, Callable] = {}


class UnregisteredAction(Exception):
    pass


def acs_action(action: Enum):
    """
    Decorator to register a new assertion consumer service action.

    :param action: the AcsAction for the decorated function
    """

    def outer(func):
        _actions[action.value] = func

        def inner(*args, **kwargs):
            return func(*args, **kwargs)

        return inner

    return outer


def schedule_action(action: Enum, sp_data: SPAuthnData) -> None:
    """
    Schedule an action to be executed after an IdP responds to a SAML request.
    This is called just before the SAML request is sent.

    TODO: This is the obsolete variant of storing a single per-SP post_authn_action in the session,
          this whole function should be removed.

    :param action: the AcsAction to schedule
    """
    current_app.logger.debug(f'Scheduling acs action {action}')
    sp_data.post_authn_action = action.value


def get_action(default_action: Optional[Enum], sp_data: SPAuthnData, authndata: Optional[SP_AuthnRequest]) -> Callable:
    """
    Retrieve an action from the registry based on the AcsAction stored in the session.

    # TODO: Make authndata not-optional and remove post_authn_action from SPAuthnData

    :return: the function to be invoked for this action
    """
    if authndata is not None:
        # NEW
        action_value = authndata.post_authn_action
    else:
        # TODO: Old, remove
        action_value = sp_data.post_authn_action
    if action_value is None:
        current_app.logger.debug(f'No post-authn-action found in the session, using default {default_action}')
        if default_action is not None:
            action_value = default_action.value
    try:
        if action_value is None:
            raise KeyError
        action = _actions[action_value.value]
    except KeyError:
        error_msg = f'"{action_value}" not found in ACS registry'
        current_app.logger.error(error_msg)
        current_app.logger.debug(f'Registered ACS actions: {_actions.keys()}')
        raise UnregisteredAction(error_msg)
    finally:
        # OLD
        current_app.logger.debug(f'Consuming (session-wide) ACS action {action_value}')
        sp_data.post_authn_action = None
        # TODO: Is there a need to flag authndata as used?

    return action
