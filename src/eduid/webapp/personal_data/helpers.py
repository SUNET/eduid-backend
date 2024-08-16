import logging
import re
from enum import unique
from typing import Optional

from eduid.common.config.base import FrontendAction
from eduid.userdb import User
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, need_authentication_response
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.authn.utils import validate_authn_for_action
from eduid.webapp.personal_data.app import current_pdata_app as current_app

logger = logging.getLogger(__name__)


@unique
class PDataMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # successfully saved personal data
    save_success = "pd.save-success"
    # validation error: missing required field
    required = "pdata.field_required"
    # display name must be made up of given name and surname
    chosen_given_name_invalid = "pdata.chosen_given_name_invalid"
    # validation error: illegal characters
    special_chars = "only allow letters"


def unique_name_parts(name: str) -> list[str]:
    """
    collect all parts of given name and surname as both separate and hyphen separated strings
    "Lars Johan Mats-Ove" -> ['Lars', 'Johan', 'Mats-Ove', 'Mats', 'Ove']
    """
    name_parts = re.split(r" ", name)
    name_parts.extend(re.split(r"[ -]", name))
    return list(set(name_parts))


def is_valid_chosen_given_name(given_name: Optional[str] = None, chosen_given_name: Optional[str] = None) -> bool:
    """
    Validate the chosen given name is made up of a combination of given_name.
    """
    if not chosen_given_name:
        return False

    given_name_parts = []
    chosen_given_name_parts = chosen_given_name.lower().split()

    if given_name:
        given_name_parts = unique_name_parts(name=given_name.lower())

    # check that at least one given name is in the chosen given name if set
    if given_name and not [part for part in given_name_parts if part in chosen_given_name_parts]:
        return False

    # check that all parts of chosen given name are in given name
    for part in given_name_parts:
        if part in chosen_given_name_parts:
            chosen_given_name_parts.remove(part)

    if not chosen_given_name_parts:
        # all parts of chosen given name are in given name
        return True

    logger.error("Display name is not made up of given name and surname")
    logger.debug(f"Allowed parts: {given_name_parts}")
    logger.debug(f"Extra characters in display name: {chosen_given_name_parts}")
    return False


def check_reauthn(frontend_action: FrontendAction, user: User) -> Optional[FluxData]:
    """Check if a re-authentication has been performed recently enough for this action"""

    authn_status = validate_authn_for_action(config=current_app.conf, frontend_action=frontend_action, user=user)
    current_app.logger.debug(f"check_reauthn called with authn status {authn_status}")
    if authn_status != AuthnActionStatus.OK:
        if authn_status == AuthnActionStatus.STALE:
            # count stale authentications to monitor if users need more time
            current_app.stats.count(name=f"{frontend_action.value}_stale_reauthn", value=1)
        return need_authentication_response(frontend_action=frontend_action, authn_status=authn_status)
    current_app.stats.count(name=f"{frontend_action.value}_successful_reauthn", value=1)
    return None
