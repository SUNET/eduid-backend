import logging
from datetime import datetime

from dateutil.parser import parse as dt_parse
from pydantic import BaseModel, model_validator

__author__ = "lundberg"


logger = logging.getLogger(__name__)


class BaseSessionInfo(BaseModel):
    issuer: str
    authn_info: list[tuple[str, list[str], str]]

    @property
    def authn_context(self) -> str | None:
        try:
            return self.authn_info[0][0]
        except KeyError:
            return None

    @property
    def authn_instant(self) -> datetime:
        return dt_parse(self.authn_info[0][2])


class SAMLAttributes(BaseModel):
    # pysaml returns attributes in lists, we never used anything other than index 0
    # so lets just do that for everything on load
    @model_validator(mode="before")
    @classmethod
    def unwind_value(cls, values: dict[str, list[str]]) -> dict[str, str]:
        # log if we get any attributes values with more than one entry
        for key, value in values.items():
            if not isinstance(value, list):
                raise ValueError("attribute value is not a list")
            if len(value) > 1:
                logger.warning(f"got attributes with {key} that has more than one value")
                logger.debug(f"attributes: {values}")
        return {key: value[0] for key, value in values.items() if value}
