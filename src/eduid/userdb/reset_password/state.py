from __future__ import annotations

import datetime
import logging
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

import bson

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.webauthn import WebauthnChallenge
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.reset_password.element import CodeElement

logger = logging.getLogger(__name__)


@dataclass
class ResetPasswordState:
    """ """

    eppn: str
    id: bson.ObjectId = field(default_factory=lambda: bson.ObjectId())
    reference: str = field(init=False)
    method: str | None = None
    created_ts: datetime.datetime = field(default_factory=utc_now)
    modified_ts: datetime.datetime | None = None
    extra_security: dict[str, Any] | None = None
    generated_password: bool = False

    def __post_init__(self) -> None:
        self.reference = str(self.id)

    def __str__(self) -> str:
        return f"<eduID {self.__class__.__name__!s}: {self.eppn!s}>"

    def to_dict(self) -> TUserDbDocument:
        res = asdict(self)
        res["eduPersonPrincipalName"] = res.pop("eppn")
        res["_id"] = res.pop("id")
        if res.get("extra_security"):
            _tokens = res["extra_security"].get("tokens")
            if isinstance(_tokens, WebauthnChallenge):
                res["extra_security"]["tokens"] = _tokens.model_dump()
        return TUserDbDocument(res)

    @classmethod
    def from_dict[TResetPasswordStateSubclass: ResetPasswordState](
        cls: type[TResetPasswordStateSubclass], data: dict[str, Any]
    ) -> TResetPasswordStateSubclass:
        data["eppn"] = data.pop("eduPersonPrincipalName")
        data["id"] = data.pop("_id")
        if "reference" in data:
            data.pop("reference")
        return cls(**data)

    def throttle_time_left(self, min_wait: datetime.timedelta) -> datetime.timedelta:
        if self.modified_ts is None or int(min_wait.total_seconds()) == 0:
            return datetime.timedelta()
        throttle_ends = self.modified_ts + min_wait
        return throttle_ends - utc_now()

    def is_throttled(self, min_wait: datetime.timedelta) -> bool:
        time_left = self.throttle_time_left(min_wait)
        if int(time_left.total_seconds()) > 0:
            logger.warning(f"Resend throttled for {time_left}")
            return True
        return False


@dataclass
class _ResetPasswordEmailStateRequired:
    """ """

    email_address: str
    email_code: CodeElement


@dataclass
class ResetPasswordEmailState(ResetPasswordState, _ResetPasswordEmailStateRequired):
    """ """

    email_reference: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        super().__post_init__()
        self.method = "email"
        self.email_code = CodeElement.parse(application="security", code_or_element=self.email_code)

    def to_dict(self) -> TUserDbDocument:
        res = super().to_dict()
        res["email_code"] = self.email_code.to_dict()
        return res


@dataclass
class _ResetPasswordEmailAndPhoneStateRequired:
    """ """

    phone_number: str
    phone_code: CodeElement


@dataclass
class ResetPasswordEmailAndPhoneState(ResetPasswordEmailState, _ResetPasswordEmailAndPhoneStateRequired):
    """ """

    def __post_init__(self) -> None:
        super().__post_init__()
        self.method = "email_and_phone"
        self.phone_code = CodeElement.parse(application="security", code_or_element=self.phone_code)

    @classmethod
    def from_email_state(
        cls: type[ResetPasswordEmailAndPhoneState],
        email_state: ResetPasswordEmailState,
        phone_number: str,
        phone_code: str,
    ) -> ResetPasswordEmailAndPhoneState:
        data = email_state.to_dict()
        data["phone_number"] = phone_number
        data["phone_code"] = phone_code
        return cls.from_dict(data=data)

    def to_dict(self) -> TUserDbDocument:
        res = super().to_dict()
        res["phone_code"] = self.phone_code.to_dict()
        return res
