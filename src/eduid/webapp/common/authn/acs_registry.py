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
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional, Union

from flask import current_app
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.proofing.methods import ProofingMethod
from eduid.webapp.common.session.namespaces import RP_AuthnRequest, SP_AuthnRequest


@dataclass
class ACSArgs:
    session_info: SessionInfo
    authn_req: Union[SP_AuthnRequest, RP_AuthnRequest]
    proofing_method: Optional[ProofingMethod] = None
    backdoor: bool = False
    user: Optional[User] = None


@dataclass
class ACSResult:
    response: Optional[WerkzeugResponse] = None
    success: bool = False
    message: Optional[TranslatableMsg] = None


# This is the list of ACS actions loaded. It is populated by decorating functions with the @acs_action.
# The keys are the AcsAction (subclass) enum values, since get_action() doesn't know which subclass of
# AcsActions that could be used to turn the string value stored in the session back into an Enum.
_actions: Dict[str, Callable[[ACSArgs], ACSResult]] = {}


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


def get_action(
    default_action: Optional[Enum], authndata: Union[SP_AuthnRequest, RP_AuthnRequest]
) -> Callable[..., ACSResult]:
    """
    Retrieve an action from the registry based on the AcsAction stored in the session.

    :return: the function to be invoked for this action
    """
    action_value = authndata.post_authn_action
    if action_value is None:
        current_app.logger.debug(f"No post-authn-action found in the session, using default {default_action}")
        if default_action is not None:
            action_value = default_action.value
    try:
        if action_value is None:
            raise KeyError
        action = _actions[action_value.value]
    except KeyError:
        error_msg = f'"{action_value}" not found in ACS registry'
        current_app.logger.error(error_msg)
        current_app.logger.debug(f"Registered ACS actions: {_actions.keys()}")
        raise UnregisteredAction(error_msg)

    return action
