__author__ = "ft"

from typing import Any

import bson
from pydantic import Field

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.proofing import EmailProofingElement
from eduid.userdb.user import User


class SignupUser(User):
    """
    Subclass of eduid.userdb.User with eduid Signup application specific data.
    """

    social_network: str | None = None
    social_network_id: str | None = None
    # The user's pending (unconfirmed) mail address.
    pending_mail_address: EmailProofingElement | None = None
    # Holds a reference id that is used for connecting msg tasks with proofing log statements.
    proofing_reference: str = Field(default_factory=lambda: str(bson.ObjectId()))

    @classmethod
    def check_or_use_data(cls, data: dict[str, Any]) -> dict[str, Any]:
        _social_network = data.pop("social_network", None)
        _social_network_id = data.pop("social_network_id", None)
        _pending_mail_address = data.pop("pending_mail_address", None)
        _proofing_reference = data.pop("proofing_reference", None)
        if _pending_mail_address:
            if isinstance(_pending_mail_address, dict):
                _pending_mail_address = EmailProofingElement.from_dict(_pending_mail_address)

        data["social_network"] = _social_network
        data["social_network_id"] = _social_network_id
        data["pending_mail_address"] = _pending_mail_address
        if _proofing_reference:
            data["proofing_reference"] = _proofing_reference

        return data

    def to_dict(self) -> TUserDbDocument:
        res = super().to_dict()
        if self.pending_mail_address is not None:
            res["pending_mail_address"] = self.pending_mail_address.to_dict()
        return res
