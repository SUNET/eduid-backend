__author__ = "ft"

import datetime
import json
import logging
from collections.abc import Mapping
from typing import Any

from bson import ObjectId

logger = logging.getLogger(__name__)


class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt: datetime.datetime | None) -> datetime.timedelta:
        return datetime.timedelta(0)

    def tzname(self, dt: datetime.datetime | None) -> str:
        return "UTC"

    def dst(self, dt: datetime.datetime | None) -> datetime.timedelta:
        return datetime.timedelta(0)


def objectid_str() -> str:
    return str(ObjectId())


def format_dict_for_debug(data: Mapping[str, Any] | None) -> str | None:
    """
    Format a dict for logging.

    :param data: The dict to format
    :return: A string
    """
    if not data:
        return None
    try:
        from eduid.common.misc.encoders import EduidJSONEncoder

        return json.dumps(data, indent=4, cls=EduidJSONEncoder)
    except Exception as e:
        # Don't need the full exception logged here, just the summary, e.g.:
        #   TypeError: Object of type UUID is not JSON serializable
        # TODO: upgrade this debug to error once we've ridded userdb of all UUIDs
        logger.debug(f"Failed formatting document for debugging using JSON encoder: {repr(e)}")
        # We fail on encoding UUIDs used in some places. We want to turn the UUIDs into strings.
        import pprint

        return pprint.pformat(data, width=120)
