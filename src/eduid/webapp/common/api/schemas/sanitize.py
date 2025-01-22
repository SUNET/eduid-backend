from collections.abc import Mapping
from typing import Any, AnyStr

from marshmallow.fields import String

from eduid.webapp.common.api.sanitation import Sanitizer

__author__ = "lundberg"


class SanitizedString(String):
    sanitizer = Sanitizer()

    def _deserialize(self, value: AnyStr, attr: str | None, data: Mapping[str, Any] | None, **kwargs: Any) -> str:
        _value = self.sanitizer.sanitize_input(untrusted_text=value)
        return super()._deserialize(_value, attr, data, **kwargs)
