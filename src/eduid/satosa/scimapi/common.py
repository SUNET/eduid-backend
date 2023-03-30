import logging
import pprint
from dataclasses import dataclass, field
from typing import Any, Generator, Mapping, Optional

from pydantic import BaseModel

import satosa.context
import satosa.internal
from saml2.mdstore import MetaData
from satosa.attribute_mapping import AttributeMapper
from satosa.micro_services.base import ResponseMicroService
from satosa.routing import STATE_KEY as ROUTER_STATE_KEY

from eduid.userdb.scimapi.userdb import ScimApiUser, ScimApiUserDB, ScimEduidUserDB

logger = logging.getLogger(__name__)


class MfaStepupAccount(BaseModel):
    entity_id: str  # the entity id of the accounts idp
    identifier: str  # the identifier of the account (eduid eppn)
    attribute: str = "eduPersonPrincipalName"  # the attribute that was used to identify the account
    assurance: str = "eduPersonAssurance"  # the attribute holding assurances in the response from the accounts idp


def store_mfa_stepup_accounts(data: satosa.internal.InternalData, accounts: list[MfaStepupAccount]) -> None:
    data.mfa_stepup_accounts = accounts


def fetch_mfa_stepup_accounts(data: satosa.internal.InternalData) -> list[MfaStepupAccount]:
    if not hasattr(data, "mfa_stepup_accounts"):
        return []
    return data.mfa_stepup_accounts


def get_metadata(context: satosa.context.Context) -> Generator[MetaData, None, None]:
    for _md_name, _metadata in context.internal_data[context.KEY_METADATA_STORE].metadata.items():
        if not isinstance(_metadata, MetaData):
            logger.debug(f"Element {_md_name} was not MetaData ({type(_metadata)})")
            continue
        yield _metadata


def get_internal_attribute_name(converter: AttributeMapper, attr_name: str) -> str:
    _int = converter.to_internal("saml", {attr_name: ["something"]})
    return list(_int.keys())[0]
