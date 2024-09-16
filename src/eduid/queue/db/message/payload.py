from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from eduid.queue.db import Payload

__author__ = "lundberg"


@dataclass
class EduidTestPayload(Payload):
    counter: int

    @classmethod
    def from_dict(cls, data: Mapping):
        return cls(**data)


@dataclass
class EduidTestResultPayload(Payload):
    """Some statistics for source/sink test runs"""

    counter: int
    first_ts: datetime
    last_ts: datetime
    delta: str  # bson can't encode timedelta
    per_second: int

    @classmethod
    def from_dict(cls, data: Mapping):
        return cls(**data)


@dataclass
class EduidSCIMAPINotification(Payload):
    data_owner: str
    post_url: str
    message: str

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)  # Do not change caller data
        return cls(**data)


@dataclass
class EmailPayload(Payload):
    email: str
    reference: str
    language: str

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)  # Do not change caller data
        return cls(**data)


@dataclass
class EduidInviteEmail(EmailPayload):
    invite_link: str
    invite_code: str
    inviter_name: str
    version: int = 1


@dataclass
class EduidSignupEmail(EmailPayload):
    verification_code: str
    site_name: str
    version: int = 1


@dataclass
class EduidResetPasswordEmail(EmailPayload):
    verification_code: str
    site_name: str
    password_reset_timeout: int  # hours
    version: int = 1


@dataclass
class EduidVerificationEmail(EmailPayload):
    verification_code: str
    site_name: str
    version: int = 1


@dataclass
class EduidTerminationEmail(EmailPayload):
    site_name: str
    version: int = 1
