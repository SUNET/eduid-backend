from copy import deepcopy
from typing import Any, ClassVar

from eduid.userdb.db.base import TUserDbDocument

__author__ = "lundberg"


# Models for filtering out unneeded or unwanted data from eduID database objects
class GenericFilterDict(dict):
    add_keys: ClassVar[list[str] | None] = None
    remove_keys: ClassVar[list[str] | None] = None

    def __init__(self, data: dict[str, Any] | None) -> None:
        """
        Create a filtered dict with allow- or denylisting of keys

        :param data: Data to filter
        :type data: dict
        """
        _data = deepcopy(data)
        super().__init__()

        if _data is None:
            pass
        elif self.add_keys:
            for key in self.add_keys:
                if key in _data:
                    self[key] = _data[key]
        elif self.remove_keys:
            for key in self.remove_keys:
                _data.pop(key, None)
            self.update(_data)
        else:
            self.update(_data)


class SupportUserFilter(GenericFilterDict):
    remove_keys: ClassVar[list[str]] = ["_id", "letter_proofing_data"]

    def __init__(self, data: TUserDbDocument) -> None:
        _data = deepcopy(data)
        super().__init__(_data)

        self["mailAliases"] = [MailAlias(alias) for alias in self.get("mailAliases", [])]
        self["passwords"] = [Credential(password) for password in self.get("passwords", [])]
        self["tou"] = [ToU(tou) for tou in self.get("tou", [])]


class SupportSignupUserFilter(GenericFilterDict):
    remove_keys: ClassVar[list[str]] = ["_id", "letter_proofing_data"]

    def __init__(self, data: TUserDbDocument) -> None:
        _data = deepcopy(data)
        super().__init__(_data)

        self["mailAliases"] = [MailAlias(alias) for alias in self.get("mailAliases", [])]
        self["passwords"] = [Credential(password) for password in self.get("passwords", [])]
        self["tou"] = [ToU(tou) for tou in self.get("tou", [])]
        self["pending_mail_address"] = PendingMailAddress(self.get("pending_mail_address"))


class MailAlias(GenericFilterDict):
    remove_keys: ClassVar[list[str]] = ["verification_code"]


class PendingMailAddress(MailAlias):
    pass


class Credential(GenericFilterDict):
    add_keys: ClassVar[list[str]] = [
        "_id",
        "credential_id",
        "created_by",
        "created_ts",
        "type",
        "success_ts",
        "authenticator",
        "authenticator_id",
        "attestation_format",
        "mfa_approved",
        "verified",
        "framework",
        "level",
        "description",
    ]


class ToU(GenericFilterDict):
    remove_keys: ClassVar[list[str]] = ["id"]


class UserAuthnInfo(GenericFilterDict):
    add_keys: ClassVar[list[str]] = ["success_ts", "fail_count", "success_count"]

    def __init__(self, data: dict[str, Any]) -> None:
        _data = deepcopy(data)
        # Remove months with 0 failures or successes
        for attrib in ["fail_count", "success_count"]:
            for key, value in data.get(attrib, {}).items():
                if value == 0:
                    del _data[attrib][key]
        super().__init__(_data)


class UserVerifications(GenericFilterDict):
    add_keys: ClassVar[list[str]] = ["verified", "obj_id", "timestamp", "model_name", "verified_timestamp"]


class UserActions(GenericFilterDict):
    add_keys: ClassVar[list[str]] = ["action", "params"]


class ProofingLogEntry(GenericFilterDict):
    add_keys: ClassVar[list[str]] = [
        "verified_data",
        "created_ts",
        "proofing_method",
        "proofing_version",
        "created_by",
        "vetting_by",
    ]

    def __init__(self, data: TUserDbDocument) -> None:
        _data = deepcopy(data)
        # Rename the verified data key to verified_data
        verified_data_names = ["nin", "mail_address", "phone_number", "orcid"]
        for name in verified_data_names:
            if name in _data:
                _data["verified_data"] = _data[name]
        super().__init__(_data)


class UserLetterProofing(GenericFilterDict):
    add_keys: ClassVar[list[str]] = ["nin", "proofing_letter"]

    class Nin(GenericFilterDict):
        add_keys: ClassVar[list[str]] = ["created_ts", "number"]

    class ProofingLetter(GenericFilterDict):
        add_keys: ClassVar[list[str]] = ["sent_ts", "is_sent", "address"]

    def __init__(self, data: dict[str, Any]) -> None:
        _data = deepcopy(data)
        super().__init__(_data)
        self["nin"] = self.Nin(self["nin"])
        self["proofing_letter"] = self.ProofingLetter(self["proofing_letter"])


class UserEmailProofing(GenericFilterDict):
    add_keys: ClassVar[list[str]] = ["verification", "modified_ts"]

    class Verification(GenericFilterDict):
        add_keys: ClassVar[list[str]] = ["created_ts", "email"]

    def __init__(self, data: TUserDbDocument) -> None:
        _data = deepcopy(data)
        super().__init__(_data)
        self["verification"] = self.Verification(self["verification"])
