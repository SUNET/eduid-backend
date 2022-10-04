# -*- coding: utf-8 -*-

from marshmallow.fields import Email

__author__ = "lundberg"


class LowercaseEmail(Email):
    """
    Email field that serializes and deserializes to a lower case string.
    """

    def _serialize(self, value, attr, obj, **kwargs):
        value = super()._serialize(value, attr, obj, **kwargs)
        return value.lower()

    def _deserialize(self, value, attr, data, **kwargs):
        value = super()._deserialize(value, attr, data, **kwargs)
        return value.lower()
