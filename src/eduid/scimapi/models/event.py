from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import Field

from eduid.common.models.scim_base import (
    BaseCreateRequest,
    BaseResponse,
    EduidBaseModel,
    SCIMResourceType,
    SCIMSchema,
    WeakVersion,
)
from eduid.userdb.scimapi import EventLevel

__author__ = "ft"


class NutidEventResource(EduidBaseModel):
    resource_type: SCIMResourceType = Field(alias="resourceType")
    scim_id: UUID = Field(alias="id")
    last_modified: datetime = Field(alias="lastModified")
    version: WeakVersion
    external_id: Optional[str] = Field(default=None, alias="externalId")
    location: Optional[str] = None


class NutidEventExtensionV1(EduidBaseModel):
    """
    All of these will be present in Events resource responses, but only some of them are required
    when creating an event: user_id, (external_id), level, data
    """

    resource: NutidEventResource
    level: EventLevel = Field(default=EventLevel.INFO)
    data: dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = Field(default=None, alias="expiresAt")
    timestamp: Optional[datetime] = None
    source: Optional[str] = None


class NutidEventV1(EduidBaseModel):
    nutid_event_v1: NutidEventExtensionV1 = Field(alias=SCIMSchema.NUTID_EVENT_V1.value)


class EventCreateRequest(BaseCreateRequest, NutidEventV1):
    pass


class EventResponse(BaseResponse, NutidEventV1):
    pass
