from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Iterable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from bson import ObjectId

from eduid.userdb.testing import MongoTestCase, SetupConfig

logger = logging.getLogger(__name__)


class CommonTestCase(MongoTestCase):
    """Base Test case for eduID webapps and workers"""

    def setUp(self, config: SetupConfig | None = None) -> None:
        """
        set up tests
        """
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        super().setUp(config=config)


def normalised_data[SomeData: dict[str, Any] | list[Any]](
    data: SomeData, replace_datetime: str | None = None, exclude_keys: list[str] | None = None
) -> SomeData:
    """Utility function for normalising data before comparisons in test cases."""

    class NormaliseEncoder(json.JSONEncoder):
        def default(self, o: object) -> Iterable:
            if isinstance(o, datetime):
                if replace_datetime is not None:
                    return replace_datetime
                # Check if datetime is timezone aware
                if o.tzinfo is not None and o.tzinfo.utcoffset(o) is not None:
                    # Raise an exception if the timezone is not equivalent to UTC
                    if o.tzinfo.utcoffset(o) != timedelta(seconds=0):
                        raise ValueError(f"Non UTC timezone found: {o.tzinfo}")
                else:
                    logger.warning(f"No timezone found for datetime: {o}")
                # Make sure all datetimes has the same type of tzinfo object
                o = o.replace(tzinfo=UTC)
                o = o.replace(microsecond=0)
                return o.isoformat()

            if isinstance(o, ObjectId | uuid.UUID | Enum | Exception):
                return str(o)

            # catch all for wierd stuff in pydantic 2 errors
            try:
                return super().default(o)
            except TypeError:
                return repr(o)

    class NormaliseDecoder(json.JSONDecoder):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(object_hook=self.object_hook, *args, **kwargs)

        def object_hook(self, o: dict) -> dict[str, Any]:
            """
            Decode any keys ending in _ts to datetime objects.

            TODO: update all tests to use the ISO format for expected data and remove this decoder,
                  keeping just the encoder above.
            """
            ret: dict[str, Any] = {}
            for key, value in o.items():
                if key.endswith("_ts") and isinstance(value, str):
                    try:
                        ret[key] = datetime.fromisoformat(value)
                        continue
                    except ValueError:
                        # The timestamp is sometimes normalised to a string that is not a timestamp (e.g. 'ts')
                        pass
                store_value = value
                if isinstance(value, list):
                    try:
                        store_value = sorted(value)
                    except TypeError:
                        # Not every list can be sorted, e.g. list of dicts.
                        #   TypeError: '<' not supported between instances of 'dict' and 'dict'
                        #
                        # We really do need stable sorting of lists of dicts though, so we crudely turn anything into
                        # strings here, and sort those.
                        _str_values = [json.dumps(x, sort_keys=True, cls=NormaliseEncoder) for x in value]
                        store_value = sorted(_str_values)
                ret[key] = store_value
            return ret

    def _exclude_keys(exclude_key: str, obj: SomeData) -> None:
        """
        remove keys from the data
        """
        if isinstance(obj, dict):
            if exclude_key in obj:
                del obj[exclude_key]
            for value in obj.values():
                _exclude_keys(exclude_key, value)
        elif isinstance(obj, list):
            for item in obj:
                _exclude_keys(exclude_key, item)

    _data = deepcopy(data)
    if exclude_keys is not None:
        for _key in exclude_keys:
            _exclude_keys(exclude_key=_key, obj=_data)
    _dumped = json.dumps(_data, sort_keys=True, cls=NormaliseEncoder)
    _loaded = json.loads(_dumped, cls=NormaliseDecoder)
    return _loaded
