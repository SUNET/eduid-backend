from typing import Any

from marshmallow.fields import Email

__author__ = "lundberg"


class LowercaseEmail(Email):
    """
    Email field that serializes and deserializes to a lower case string.
    """

    def _serialize(self, value: str | bytes, attr: Any, obj: Any, **kwargs: Any):
        _value = super()._serialize(value, attr, obj, **kwargs)
        if _value is None:
            return None
        return _value.lower()

    def _deserialize(self, value: str | bytes, attr: Any, data: Any, **kwargs: Any):
        _value = super()._deserialize(value, attr, data, **kwargs)
        return _value.lower()
