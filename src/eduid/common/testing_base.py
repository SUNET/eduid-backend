#
# Copyright (c) 2016 NORDUnet A/S
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
from __future__ import annotations

import json
import logging
import logging.config
import os
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Sequence, Union

from eduid.common.logging import LocalContext, make_dictConfig
from eduid.userdb.testing import MongoTestCase

logger = logging.getLogger(__name__)


class CommonTestCase(MongoTestCase):
    """Base Test case for eduID webapps and workers"""

    def setUp(self, *args, **kwargs):
        """
        set up tests
        """
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        super().setUp(*args, **kwargs)


# This is the normalised_data that should be used
def normalised_data(
    data: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]], replace_datetime: Any = None
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Utility function for normalising dicts (or list of dicts) before comparisons in test cases."""

    class SortEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, datetime):
                return str(_normalise_value(obj))
            if isinstance(obj, Enum):
                return _normalise_value(obj)
            if isinstance(obj, uuid.UUID):
                return str(obj)
            return json.JSONEncoder.default(self, obj)

    def _any_key(value: Any):
        """Helper function to be able to use sorted with key argument for everything"""
        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True, cls=SortEncoder)  # Turn dict in to a string for sorting
        return value

    def _normalise_value(data: Any) -> Any:
        if isinstance(data, dict) or isinstance(data, list):
            return normalised_data(data, replace_datetime=replace_datetime)
        elif isinstance(data, datetime):
            if replace_datetime is not None:
                return replace_datetime
            # Check if datetime is timezone aware
            if data.tzinfo is not None and data.tzinfo.utcoffset(data) is not None:
                # Raise an exception if the timezone is not equivalent to UTC
                if data.tzinfo.utcoffset(data) != timedelta(seconds=0):
                    raise ValueError(f"Non UTC timezone found: {data.tzinfo}")
            else:
                logger.warning(f"No timezone found for datetime: {data}")
            # Make sure all datetimes has the same type of tzinfo object
            data = data.replace(tzinfo=timezone.utc)
            return data.replace(microsecond=0)
        elif isinstance(data, Enum):
            return f"{repr(data)}"
        return data

    if isinstance(data, list):
        # Recurse into lists of dicts. mypy (correctly) says this recursion can in fact happen
        # more than once, so the result can be a list of list of dicts or whatever, but the return
        # type becomes too bloated with that in mind and the code becomes too inelegant when unrolling
        # this list comprehension into a for-loop checking types for something only intended to be used in test cases.
        # Hence the type: ignore.
        return sorted([_normalise_value(x) for x in data], key=_any_key)  # type: ignore
    elif isinstance(data, dict):
        # normalise all values found in the dict, returning a new dict (to not modify callers data)
        return {k: _normalise_value(v) for k, v in data.items()}
    raise TypeError("normalised_data not called on dict (or list of dicts)")
