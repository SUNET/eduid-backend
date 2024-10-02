"""
Registry for actions to be performed after an IdP sends a POST
request in response to a SAML request initiated by the service

The actions are defined in the acs_actions module,
and they are performed in the assertion consumer service view,
and are called with two positional parameters:

 * the session_info given in the SAML response (a dict)
 * The user object
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

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
    authn_req: SP_AuthnRequest | RP_AuthnRequest
    proofing_method: ProofingMethod | None = None
    backdoor: bool = False
    user: User | None = None


@dataclass
class ACSResult:
    response: WerkzeugResponse | None = None
    success: bool = False
    message: TranslatableMsg | None = None


# This is the list of ACS actions loaded. It is populated by decorating functions with the @acs_action.
# The keys are the AcsAction (subclass) enum values, since get_action() doesn't know which subclass of
# AcsActions that could be used to turn the string value stored in the session back into an Enum.
_actions: dict[str, Callable[[ACSArgs], ACSResult]] = {}


class UnregisteredAction(Exception):
    pass


def acs_action(action: Enum) -> Callable:
    """
    Decorator to register a new assertion consumer service action.

    :param action: the AcsAction for the decorated function
    """

    def outer(func: Callable[[ACSArgs], ACSResult]) -> Callable[[ACSArgs], ACSResult]:
        _actions[action.value] = func

        def inner(*args: Any, **kwargs: Any) -> ACSResult:
            return func(*args, **kwargs)

        return inner

    return outer


def get_action(default_action: Enum | None, authndata: SP_AuthnRequest | RP_AuthnRequest) -> Callable[..., ACSResult]:
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
