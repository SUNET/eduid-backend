__author__ = "eperez"

import logging

from eduid.userdb.idp import IdPUser
from eduid.webapp.idp.app import current_idp_app as current_app

logger = logging.getLogger(__name__)


def need_tou_acceptance(user: IdPUser) -> bool:
    """
    Check if the user is required to accept a new version of the Terms of Use,
    in case the IdP configuration points to a version the user hasn't accepted,
    or the old acceptance was too long ago.
    """
    version = current_app.conf.tou_version
    interval = current_app.conf.tou_reaccept_interval

    if user.tou.has_accepted(version, int(interval.total_seconds())):
        logger.debug(f"User has already accepted ToU version {version!r}")
        return False

    tous = [x.version for x in user.tou.to_list()]
    logger.info(f"User needs to accepted ToU version {version!r} (has accepted: {tous})")

    return True
