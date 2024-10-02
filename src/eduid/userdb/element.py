"""
userdb data
===========

userdb data can be in 2 different formats, which I will call here pythonic and
eduid formats. In both cases, the data is in the form of sets of attributes with
values of arbitrary types.

In Python code we deal with data in pythonic format. Outside Python code (in
the DB, or when sending data to the front, or also in data samples for testing)
we deal with data in eduid format.

The interface between both formats is given by the `Element`'s methods
`from_dict` (to convert data in eduid format to data in pythonic format) and
`to_dict` (to convert data in the opposite direction).

The main differences between both formats are, in one hand, the names of the
attributes, that may change from one format to the other. For example, the
pythonic attribute `is_verified` is generally translated to eduid format as
`verified`.

On another hand, the representation of complex data (i.e., not of basic types:
string, boolean, integer, bytes), differs: in pythonic format is in the form of
dataclass objects, and in eduid format is in the form of dictionaries / JSON.

Additionally, some of the attribute names that were used in the past have been
deprecated. An example is the pythonic attribute name `created_by`, which in
some elements was translated to eduid format as `source`. We want to be able to
ingest (in `from_dict`) data in the old format.

There is also sometimes data in the eduid format dicts that we simply want
to ignore. An example is `verification_code` in VerifiedElement.

Finally, when ingesting external data (in eduid format) we may want to enforce
any number of arbitrary constraints (in `from_dict`), to make sure the data is
semantically sound. For example, we don't want data representing an element
with the `is_primary` attribute set to `True` but the `is_verified` attribute
set to `False`.

To translate between the data formats, and to enforce arbitrary constraints we
provide 2 methods, `_from_dict_transform` and `_to_dict_transform`, that are
respectively called in `from_dict` and `to_dict` and can be overridden in
subclasses.

"""

from __future__ import annotations

import copy
from abc import ABC
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Any, Generic, NewType, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import EduIDUserDBError, UserDBValueError

__author__ = "ft"

from eduid.userdb.util import utc_now


class ElementError(EduIDUserDBError):
    """
    Base exception class for PrimaryElement errors.
    """

    pass


class PrimaryElementError(ElementError):
    """
    Base exception class for PrimaryElement errors.
    """

    pass


class PrimaryElementViolation(PrimaryElementError):
    """
    Raised when some operation would result in more or less than one 'primary'
    element in an PrimaryElementList.
    """

    pass


TElementSubclass = TypeVar("TElementSubclass", bound="Element")
ElementKey = NewType("ElementKey", str)


class Element(BaseModel):
    """
    Base class for elements.

    Hierarchy:

        Element
            VerifiedElement
                PrimaryElement
            EventElement
    """

    created_by: str | None = Field(default=None, alias="source")
    created_ts: datetime = Field(default_factory=utc_now, alias="added_timestamp")
    modified_ts: datetime = Field(default_factory=utc_now)
    # This is a short-term hack to deploy new dataclass based elements without
    # any changes to data in the production database. Remove after a burn-in period.
    no_created_ts_in_db: bool = Field(default=False, exclude=True)
    no_modified_ts_in_db: bool = Field(default=False, exclude=True)
    model_config = ConfigDict(
        populate_by_name=True, validate_assignment=True, extra="forbid", arbitrary_types_allowed=True
    )

    def __str__(self) -> str:
        return f"<eduID {self.__class__.__name__}: {self.dict()}>"

    @classmethod
    def from_dict(cls: type[TElementSubclass], data: Mapping[str, Any]) -> TElementSubclass:
        """
        Construct element from a data dict in eduid format.
        """
        if not isinstance(data, dict):
            raise UserDBValueError(f"Invalid data: {data}")

        _data = copy.deepcopy(data)  # to not modify callers data

        _data = cls._from_dict_transform(_data)

        return cls(**_data)

    def to_dict(self) -> TUserDbDocument:
        """
        Convert Element to a dict in eduid format, that can be used to reconstruct the
        Element later.
        """
        data = self.dict(exclude_none=True)

        data = self._to_dict_transform(data)

        return TUserDbDocument(data)

    @classmethod
    def _from_dict_transform(cls: type[TElementSubclass], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        if "application" in data:
            data["created_by"] = data.pop("application")

        if "added_timestamp" in data:
            data["created_ts"] = data.pop("added_timestamp")

        if "created_ts" not in data or isinstance(data.get("created_ts"), bool):
            # some really old nin entries in the database have neither created_ts nor modified_ts
            data["no_created_ts_in_db"] = True
            data["created_ts"] = datetime.fromisoformat("1900-01-01T00:00:00+00:00")

        if "modified_ts" not in data or isinstance(data.get("modified_ts"), bool):
            data["no_modified_ts_in_db"] = True
            # Use created_ts as modified_ts if no explicit modified_ts was found
            data["modified_ts"] = data["created_ts"]

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        # If there was no modified_ts in the data that was loaded from the database,
        # don't write one back if it matches the implied one of created_ts
        if self.no_modified_ts_in_db is True:
            if data.get("modified_ts") == data.get("created_ts"):
                del data["modified_ts"]

        if self.no_created_ts_in_db is True:
            if "created_ts" in data:
                del data["created_ts"]

        return data

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key in an ElementList.
        Must be implemented in subclasses of Element.
        """
        raise NotImplementedError("'key' not implemented for Element subclass")


TVerifiedElementSubclass = TypeVar("TVerifiedElementSubclass", bound="VerifiedElement")


class VerifiedElement(Element, ABC):
    """
    Elements that can be verified or not.
    """

    is_verified: bool = Field(default=False, alias="verified")
    verified_by: str | None = None
    verified_ts: datetime | None = None
    proofing_method: Enum | None = None
    proofing_version: str | None = None

    def __str__(self) -> str:
        return f"<eduID {self.__class__.__name__}(key={repr(self.key)}): verified={self.is_verified}>"

    @classmethod
    def _from_dict_transform(cls: type[TVerifiedElementSubclass], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data from eduid database format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "verified" in data:
            data["is_verified"] = data.pop("verified")

        if "verification_code" in data:
            del data["verification_code"]

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid database format.
        """
        if "is_verified" in data:
            data["verified"] = data.pop("is_verified")

        data = super()._to_dict_transform(data)

        return data


TPrimaryElementSubclass = TypeVar("TPrimaryElementSubclass", bound="PrimaryElement")


class PrimaryElement(VerifiedElement, ABC):
    """
    Elements that can be either primary or not.
    """

    is_primary: bool = Field(default=False, alias="primary")  # primary is the old name

    def __setattr__(self, key: str, value: Any) -> None:
        """
        raise PrimaryElementViolation when trying to set a primary element as unverified
        """
        if key == "is_verified" and value is False and self.is_primary is True:
            raise PrimaryElementViolation("Can't remove verified status of primary element")

        super().__setattr__(key, value)

    def __str__(self) -> str:
        return (
            f"<eduID {self.__class__.__name__}(key={repr(self.key)}): "
            f"primary={self.is_primary}, verified={self.is_verified}>"
        )

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into database format.
        """
        if "is_primary" in data:
            data["primary"] = data.pop("is_primary")

        data = super()._to_dict_transform(data)

        return data


ListElement = TypeVar("ListElement", bound=Element)
MatchingElement = TypeVar("MatchingElement", bound=Element)


class ElementList(BaseModel, Generic[ListElement], ABC):
    """
    Hold a list of Element instances.

    Provide methods to find, add and remove elements from the list.
    """

    elements: list[ListElement] = Field(default=[])
    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    def __str__(self) -> str:
        return "<eduID {!s}: {!r}>".format(self.__class__.__name__, getattr(self, "elements", None))

    @field_validator("elements", mode="before")
    @classmethod
    def _validate_element_values(cls, values: list[ListElement]) -> list[ListElement]:
        cls._validate_elements(values)
        return values

    @classmethod
    def _validate_elements(cls, values: list[ListElement]) -> list[ListElement]:
        """
        Validate elements. Since the 'elements' property is defined on subclasses
        (to get the right type information), a pydantic validator can't be placed here
        on the superclass.
        """
        # Ensure no elements have duplicate keys
        for this in values:
            if not isinstance(this, Element):
                raise ValueError(f"Value is of type {type(this)} which is not an Element subclass")
            same_key = [x for x in values if x.key == this.key]
            if len(same_key) != 1:
                raise ValueError(f"Duplicate element key: {repr(this.key)}")
        return values

    @classmethod
    def from_list_of_dicts(cls, items: list[dict[str, Any]]):
        # must be implemented by subclass to get correct type information
        raise NotImplementedError()

    def to_list(self) -> list[ListElement]:
        """
        Return the list of elements as a list.

        :return: List of elements
        """
        return self.elements

    def to_list_of_dicts(self) -> list[dict[str, Any]]:
        """
        Get the elements in a serialized format that can be stored in MongoDB.

        :return: List of dicts
        """
        return [this.to_dict() for this in self.elements if isinstance(this, Element)]

    def find(self, key: ElementKey | str | None) -> ListElement | None:
        """
        Find an Element from the element list, using the key.

        :param key: the key to look for in the list of elements
        :return: Element found, if any
        """
        if not key:
            # Allow None as argument to not have to check for None before calling find everywhere
            return None
        res = [x for x in self.elements if isinstance(x, Element) and x.key == key]
        if not res:
            return None
        if len(res) > 1:
            raise EduIDUserDBError("More than one element found")
        return res[0]

    def add(self, element: ListElement) -> None:
        """
        Add an element to the list.

        :param element: Element
        :return: None
        """
        self.elements += [element]
        return None

    def remove(self, key: ElementKey) -> None:
        """
        Remove an existing Element from the list.

        :param key: Key of element to remove
        :return: None
        """
        match = self.find(key)
        if not match:
            raise UserDBValueError("Element not found in list")

        self.elements = [this for this in self.elements if this != match]

        return None

    def filter(self, cls: type[MatchingElement]) -> list[MatchingElement]:
        """
        Return a new ElementList with the elements that were instances of cls.

        :param cls: Class of interest
        :return: List with matching elements
        """
        return [x for x in self.elements if isinstance(x, cls)]

    @property
    def count(self) -> int:
        """
        Return the number of elements in the list
        """
        return len(self.elements)


class VerifiedElementList(ElementList[ListElement], Generic[ListElement], ABC):
    """
    Hold a list of VerifiedElement instances.

    Provides methods specific for a collection of verified elements.
    """

    @property
    def verified(self) -> list[ListElement]:
        """
        Get all the verified elements in the ElementList.

        """
        verified_elements = [e for e in self.elements if isinstance(e, VerifiedElement) and e.is_verified]
        # mypy figures out the real type of `verified_elements' since isinstance() is used above and complains
        #    error: Incompatible return value type (got "List[VerifiedElement]", expected "List[ListElement]")
        return verified_elements  # type: ignore


class PrimaryElementList(VerifiedElementList[ListElement], Generic[ListElement], ABC):
    """
    Hold a list of PrimaryElement instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary element in the list (except if the list is empty or there are
    no confirmed elements).
    """

    @classmethod
    def _validate_elements(cls, values: list[ListElement]):
        """
        Validate elements. Since the 'elements' property is defined on subclasses
        (to get the right type information), a pydantic validator can't be placed here
        on the superclass.
        """
        super()._validate_elements(values)
        # call _get_primary to validate the elements - will raise an exception on errors
        cls._get_primary(values)
        return values

    @property
    def primary(self) -> ListElement | None:
        """
        :return: Return the primary Element.

        There must always be exactly one primary element if there are confirmed
        elements in the list, and exactly zero if there are no confirmed elements, so a
        PrimaryElementViolation is raised in case any of these assertions do not hold.
        """

        _primary = [x for x in self.elements if isinstance(x, PrimaryElement) and x.is_primary]

        if not _primary:
            return None

        if len(_primary) != 1:
            raise UserDBValueError(f"More than one primary element found ({_primary})")

        match = _primary[0]

        if not isinstance(match, PrimaryElement):
            raise UserDBValueError(f"Primary element {repr(match)} is not of type PrimaryElement")

        # mypy figures out the real type of match since isinstance() is used above and complains
        #    error: Incompatible return value type (got "PrimaryElement", expected "Optional[ListElement]")
        return match  # type: ignore

    def set_primary(self, key: ElementKey) -> None:
        """
        Mark element as the users primary element.

        This is a ElementList operation since it needs to atomically update more than one
        element in the list. Marking an element as primary will result in some other element
        loosing it's primary status.

        :param key: the key of the element to set as primary
        """
        match = self.find(key)

        if not match:
            raise UserDBValueError("Element not found in list, can't set as primary")

        if not isinstance(match, PrimaryElement):
            raise UserDBValueError(f"Primary element {repr(match)} is not of type PrimaryElement")

        if not match.is_verified:
            raise PrimaryElementViolation("Primary element must be verified")

        # Go through the whole list. Mark element as primary and all other as *not* primary.
        # Build a new list and re-assign to make sure the validators run.
        new = []
        for this in self.elements:
            if not isinstance(this, PrimaryElement):
                raise UserDBValueError(f"Element {repr(this)} is not of type PrimaryElement")
            this.is_primary = bool(this.key == key)
            new += [this]
        # mypy figures out the real type of `new' since isinstance() is used above and complains
        #    error: Incompatible types in assignment (expression has type "List[PrimaryElement]",
        #           variable has type "List[ListElement]")
        self.elements = new  # type: ignore

    @classmethod
    def _get_primary(cls, elements: list[ListElement]) -> ListElement | None:
        """
        Find the primary element in a list, and ensure there is exactly one (unless
        there are no confirmed elements, in which case, ensure there are exactly zero).

        :param elements: List of Element instances
        :return: Primary Element
        """
        if not elements:
            return None

        res = [x for x in elements if isinstance(x, PrimaryElement) and x.is_primary is True]
        if not res:
            return None

        if len(res) != 1:
            _name = cls.__class__.__name__
            raise PrimaryElementViolation(f"{_name} contains {len(res)}/{len(elements)} primary elements")

        primary = res[0]
        if not primary.is_verified:
            raise PrimaryElementViolation("Primary element is not verified")

        # mypy figures out the real type of `res[0]' since isinstance() is used above and complains
        #    error: Incompatible return value type (got "PrimaryElement", expected "Optional[ListElement]")
        return res[0]  # type: ignore

    def remove(self, key: ElementKey) -> None:
        """
        Remove an existing Element from the list. Removing the primary element is not allowed.
        :param key: Key of element to remove
        """
        match = self.find(key)
        if not match:
            raise UserDBValueError("Element not found in list")

        if isinstance(match, PrimaryElement) and match.is_primary and self.count > 1:
            # This is not allowed since a PrimaryElementList with any entries in it must have a primary
            raise PrimaryElementViolation("Removing the primary element is not allowed")

        self.elements = [this for this in self.elements if this != match]

        return None

    def remove_handling_primary(self, key: ElementKey) -> None:
        """Remove an element from the list. If the element is primary, first promote
        any other present verified element to primary in order to not get a PrimaryElementViolation.

        TODO: This should perhaps be done in the regular `remove' method of PrimaryElementList,
              but I did not want to change those semantics in this PR.
        """
        elem = self.find(key)
        if not elem:
            return None

        # Assure the type checking system that elements are PrimaryElement
        if not isinstance(elem, PrimaryElement):
            return None

        if elem.is_primary:
            # Look for other verified elements
            other_verified = [x for x in self.verified if isinstance(x, PrimaryElement) and x.key != key]
            if other_verified:
                # Promote the first other verified element found to primary
                self.set_primary(other_verified[0].key)
            else:
                elem.is_primary = False

        self.remove(key)
        return None
