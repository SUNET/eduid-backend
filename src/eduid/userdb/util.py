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
# Author : Fredrik Thulin <fredrik@thulin.net>
#
__author__ = "ft"

import datetime
import json
import logging
from typing import Any, Mapping, Optional

from bson import ObjectId

logger = logging.getLogger(__name__)


class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


# NOTE: This function is copied from eduid.webapp.common.misc.timeutil because eduid-userdb can't import eduid.webapp.common
def utc_now() -> datetime.datetime:
    """Return current time with tz=UTC"""
    return datetime.datetime.now(tz=datetime.timezone.utc)


def objectid_str() -> str:
    return str(ObjectId())


def format_dict_for_debug(data: Optional[Mapping[str, Any]]) -> Optional[str]:
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
        # Don't need the full exception logged here, just the summary (e.g.
        #   TypeError: Object of type UUID is not JSON serializable
        # )
        # TODO: upgrade this debug to error once we've ridded userdb of all UUIDs
        logger.debug(f"Failed formatting document for debugging using JSON encoder: {repr(e)}")
        # We fail on encoding UUIDs used in some places. We want to turn the UUIDs into strings.
        import pprint

        return pprint.pformat(data, width=120)
