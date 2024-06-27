from __future__ import annotations

import json
import logging
import typing
import uuid
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional

from bson import ObjectId
from flask import request
from pydantic import BaseModel, ConfigDict, Field

from eduid.common.misc.encoders import EduidJSONEncoder
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import User
from eduid.userdb.db import BaseDB
from eduid.webapp.common.api.utils import make_short_code
from eduid.webapp.idp.assurance_data import UsedCredential
from eduid.webapp.idp.idp_saml import ServiceInfo
from eduid.webapp.idp.mischttp import get_user_agent
from eduid.webapp.idp.other_device.data import OtherDeviceId, OtherDeviceState

if typing.TYPE_CHECKING:
    from eduid.webapp.idp.login_context import LoginContext

logger = logging.getLogger(__name__)


class Device1Data(BaseModel):
    ref: str  # the login 'ref' on device 1 (where login using another device was initiated)
    authn_context: Optional[EduidAuthnContextClass] = None  # the level of authentication required on device 1
    request_id: Optional[str] = None  # the request ID on device 1 (SAML authnRequest request id for example)
    reauthn_required: bool  # if reauthn is required for the login on device 1
    ip_address: str  # the IP address of device 1, to be used by the user on device 2 to assess the request
    user_agent: Optional[str] = (
        None  # the user agent of device 1, to be used by the user on device 2 to assess the request
    )
    service_info: Optional[ServiceInfo] = None  # information about the service (SP) where the user is logging in
    is_known_device: bool  # device 1 is a device that has previously logged in as state.eppn


class Device2Data(BaseModel):
    ref: Optional[str] = None  # the pending_request 'ref' on device 2
    response_code: Optional[str] = None  # code from login event (using device 2) that has to be entered on device 1
    # TODO: doesn't work with onetime_credentials
    credentials_used: list[UsedCredential] = Field(default=[])


class OtherDevice(BaseModel):
    bad_attempts: int = 0  # number of failed attempts to produce the right response_code
    created_at: datetime
    device1: Device1Data
    device2: Device2Data
    eppn: Optional[str] = (
        None  # the eppn of the user on device 1, either from the SSO session or derived from e-mail address
    )
    expires_at: datetime
    obj_id: ObjectId = Field(default_factory=ObjectId, alias="_id")
    display_id: str = Field(repr=False)  # id number shown to the user on both devices, to match up screens
    state: OtherDeviceState  # the state this request is in
    state_id: OtherDeviceId  # unique reference for this state
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @classmethod
    def from_parameters(
        cls: type[OtherDevice],
        ticket: LoginContext,
        eppn: Optional[str],
        authn_context: Optional[EduidAuthnContextClass],
        ip_address: str,
        user_agent: Optional[str],
        ttl: timedelta,
    ) -> OtherDevice:
        _uuid = uuid.uuid4()
        short_code = make_short_code()
        now = utc_now()
        if not eppn and ticket.known_device:
            eppn = ticket.known_device.data.eppn
        _is_known_device = False
        if ticket.known_device and ticket.known_device.data.eppn == eppn and eppn:
            # If is_known_device is true, the user won't have to enter the response code from device 2 on device 1
            _is_known_device = True
        return cls(
            state_id=OtherDeviceId(str(_uuid)),
            state=OtherDeviceState.NEW,
            display_id=short_code,
            eppn=eppn,
            device1=Device1Data(
                ref=ticket.request_ref,
                authn_context=authn_context,
                request_id=ticket.request_id,
                ip_address=ip_address,
                user_agent=user_agent,
                reauthn_required=ticket.reauthn_required,
                service_info=ticket.service_info,
                is_known_device=_is_known_device,
            ),
            device2=Device2Data(),
            created_at=now,
            expires_at=now + ttl,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.dict()

    def to_json(self):
        """For debug logging ONLY. Redacts the response code if set."""
        data = self.to_dict()
        if data["device2"]["response_code"]:
            data["device2"]["response_code"] = "REDACTED"
        return json.dumps(data, indent=4, cls=EduidJSONEncoder)

    @classmethod
    def from_dict(cls: type[OtherDevice], data: Mapping[str, Any]) -> OtherDevice:
        return cls(**data)


class OtherDeviceDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_idp", collection: str = "other_device"):
        super().__init__(db_uri, db_name, collection=collection)

        indexes = {
            "auto-discard": {"key": [("expires_at", 1)], "expireAfterSeconds": 0},
            "unique-state-id": {"key": [("state_id", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    def save(self, state: OtherDevice) -> bool:
        """
        Add a new OtherDevice to the database, or update an existing one.
        """
        result = self._coll.replace_one({"_id": state.obj_id}, state.to_dict(), upsert=True)
        logger.debug(
            f"Saved OtherDevice {state} in the db: "
            f"matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}"
        )
        return result.acknowledged

    def get_state_by_id(self, state_id: OtherDeviceId) -> Optional[OtherDevice]:
        state = self._get_document_by_attr("state_id", str(state_id))
        if not state:
            logger.debug(f"Other-device state with state_id {state_id} not found in the database")
            return None
        return OtherDevice.from_dict(state)

    def add_new_state(self, ticket: LoginContext, user: Optional[User], ttl: timedelta) -> OtherDevice:
        user_agent = None
        ua = get_user_agent()
        if ua:
            user_agent = str(ua.parsed)

        if not request.remote_addr:
            raise RuntimeError("No remote address in request")

        authn_ref = ticket.get_requested_authn_context()
        state = OtherDevice.from_parameters(
            ticket=ticket,
            authn_context=authn_ref,
            eppn=None if not user else user.eppn,
            ip_address=request.remote_addr,
            ttl=ttl,
            user_agent=user_agent,
        )
        res = self.save(state)
        logger.debug(f"Save {state.state_id} result: {res}")
        logger.info(f"Created other-device state: {state.state_id}")
        logger.debug(f"   Full other-device state: {state.to_json()}")
        return state

    def abort(self, state: OtherDevice) -> Optional[OtherDevice]:
        """
        Abort a state.

        It may be aborted in the states NEW and IN_PROGRESS from device #1,
        and in the state AUTHENTICATED on device #2.
        """
        if state.state not in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS, OtherDeviceState.AUTHENTICATED]:
            return None
        _state_val = state.state.value
        state.state = OtherDeviceState.ABORTED

        result = self._coll.replace_one({"_id": state.obj_id, "state": _state_val}, state.to_dict(), upsert=True)
        logger.debug(
            f"Aborted OtherDevice {state} in the db: "
            f"matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}"
        )
        if not result.acknowledged:
            return None
        return state

    def grab(self, state: OtherDevice, device2_ref: str) -> Optional[OtherDevice]:
        """
        Grab a state, on device 2. This has to be an atomic operation to ensure two devices (one attacker and one
        victim) can't have pending_requests pointing at this very same OtherDevice state. Otherwise, the attacker
        can retrieve the response_code after the victim logs in.
        """
        if state.state != OtherDeviceState.NEW:
            return None

        if state.device2.ref is not None:
            return None

        _state_val = state.state.value
        state.state = OtherDeviceState.IN_PROGRESS
        state.device2.ref = device2_ref

        result = self._coll.replace_one({"_id": state.obj_id, "state": _state_val}, state.to_dict(), upsert=True)
        logger.debug(
            f"Grabbed OtherDevice {state} in the db: "
            f"matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}"
        )
        if not result.acknowledged:
            return None
        return state

    def logged_in(self, state: OtherDevice, eppn: str, credentials_used: list[UsedCredential]) -> Optional[OtherDevice]:
        """
        Finish a state, on device 2.
        """
        if state.state != OtherDeviceState.IN_PROGRESS:
            return None

        if not state.device2.ref:
            return None

        if (state.eppn and state.eppn != eppn) or not eppn:
            logger.error(f"Can't record use other device as finished for eppn {eppn} (state has eppn {state.eppn})")
            return None

        _state_val = state.state.value
        state.state = OtherDeviceState.AUTHENTICATED
        state.eppn = eppn
        state.device2.credentials_used = credentials_used
        state.device2.response_code = make_short_code()

        result = self._coll.replace_one({"_id": state.obj_id, "state": _state_val}, state.to_dict(), upsert=True)
        logger.debug(
            f"Finished OtherDevice {state} in the db: "
            f"matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}"
        )
        if not result.acknowledged:
            return None
        return state
