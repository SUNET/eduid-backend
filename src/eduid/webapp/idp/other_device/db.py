from __future__ import annotations

import json
import logging
import os
import typing
import uuid
from datetime import datetime, timedelta
from typing import Any, List, Mapping, Optional, Type

from bson import ObjectId
from flask import request
from pydantic import BaseModel, Field

from eduid.common.misc.encoders import EduidJSONEncoder
from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.db import BaseDB
from eduid.webapp.idp.assurance_data import EduidAuthnContextClass, UsedCredential
from eduid.webapp.idp.other_device.data import OtherDeviceId, OtherDeviceState

if typing.TYPE_CHECKING:
    from eduid.webapp.common.session.logindata import LoginContext

logger = logging.getLogger(__name__)


class Device1Data(BaseModel):
    ref: str  # the login 'ref' on device 1 (where login using another device was initiated)
    authn_context: Optional[EduidAuthnContextClass]  # the level of authentication required on device 1
    request_id: Optional[str]  # the request ID on device 1 (SAML authnRequest request id for example)
    reauthn_required: bool  # if reauthn is required for the login on device 1
    ip_address: str  # the IP address of device 1, to be used by the user on device 2 to assess the request
    user_agent: Optional[str]  # the user agent of device 1, to be used by the user on device 2 to assess the request


class Device2Data(BaseModel):
    ref: Optional[str] = None  # the pending_request 'ref' on device 2
    response_code: Optional[str] = None  # code from login event (using device 2) that has to be entered on device 1
    # TODO: doesn't work with onetime_credentials
    credentials_used: List[UsedCredential] = Field(default=[])


class OtherDevice(BaseModel):
    bad_attempts: int = 0  # number of failed attempts to produce the right response_code
    created_at: datetime
    device1: Device1Data
    device2: Device2Data
    eppn: Optional[str]  # the eppn of the user on device 1, either from the SSO session or entered e-mail address
    expires_at: datetime
    obj_id: ObjectId = Field(default_factory=ObjectId, alias='_id')
    short_code: str = Field(repr=False)  # short code shown to the user on both devices, to match up screens
    state: OtherDeviceState  # the state this request is in
    state_id: OtherDeviceId  # unique reference for this state

    class Config:
        # Don't reject ObjectId
        arbitrary_types_allowed = True

    @classmethod
    def from_parameters(
        cls: Type[OtherDevice],
        eppn: Optional[str],
        device1_ref: str,
        authn_context: Optional[EduidAuthnContextClass],
        request_id: Optional[str],
        ip_address: str,
        user_agent: Optional[str],
        ttl: timedelta,
        reauthn_required: bool = False,
    ) -> OtherDevice:
        _uuid = uuid.uuid4()
        short_code = make_short_code()
        now = utc_now()
        return cls(
            state_id=OtherDeviceId(str(_uuid)),
            state=OtherDeviceState.NEW,
            short_code=short_code,
            eppn=eppn,
            device1=Device1Data(
                ref=device1_ref,
                authn_context=authn_context,
                request_id=request_id,
                ip_address=ip_address,
                user_agent=user_agent,
                reauthn_required=reauthn_required,
            ),
            device2=Device2Data(),
            created_at=now,
            expires_at=now + ttl,
        )

    def to_dict(self) -> Mapping[str, Any]:
        return self.dict()

    def to_json(self):
        """ For debug logging ONLY. Redacts the response code if set. """
        data = self.to_dict()
        if data['device2']['response_code']:
            data['device2']['response_code'] = 'REDACTED'
        return json.dumps(data, indent=4, cls=EduidJSONEncoder)

    @classmethod
    def from_dict(cls: Type[OtherDevice], data: Mapping[str, Any]) -> OtherDevice:
        return cls(**data)


def make_short_code(digits: int = 6) -> str:
    """ Make a short decimal code, left-padded with zeros to the width specified by `digits'. """
    code = int.from_bytes(os.urandom(4), byteorder='big') % 1000000
    return str(code).zfill(digits)


class OtherDeviceDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = 'eduid_idp', collection: str = 'other_device'):
        super().__init__(db_uri, db_name, collection=collection)

        indexes = {
            'auto-discard': {'key': [('expires_at', 1)], 'expireAfterSeconds': 0},
            'unique-state-id': {'key': [('state_id', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def save(self, state: OtherDevice) -> bool:
        """
        Add a new OtherDevice to the database, or update an existing one.
        """
        result = self._coll.replace_one({'_id': state.obj_id}, state.to_dict(), upsert=True)
        logger.debug(
            f'Saved OtherDevice {state} in the db: '
            f'matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}'
        )
        return result.acknowledged

    def get_state_by_id(self, state_id: OtherDeviceId) -> Optional[OtherDevice]:
        state = self._get_document_by_attr('state_id', str(state_id))
        if not state:
            logger.debug(f'Other-device state with state_id {state_id} not found in the database')
            return None
        return OtherDevice.from_dict(state)

    def add_new_state(self, ticket: 'LoginContext', user: Optional[User], ttl: timedelta) -> OtherDevice:
        authn_ref = ticket.get_requested_authn_context()
        state = OtherDevice.from_parameters(
            eppn=None if not user else user.eppn,
            device1_ref=ticket.request_ref,
            authn_context=authn_ref,
            request_id=ticket.request_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('user-agent'),
            ttl=ttl,
        )
        res = self.save(state)
        logger.debug(f'Save {state.state_id} result: {res}')
        logger.info(f'Created other-device state: {state.state_id}')
        logger.debug(f'   Full other-device state: {state.to_json()}')
        return state

    def abort(self, state: OtherDevice) -> Optional[OtherDevice]:
        """
        Abort a state.
        """
        if state.state not in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]:
            return None
        _state_val = state.state.value
        state.state = OtherDeviceState.ABORTED

        result = self._coll.replace_one({'_id': state.obj_id, 'state': _state_val}, state.to_dict(), upsert=True)
        logger.debug(
            f'Aborted OtherDevice {state} in the db: '
            f'matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}'
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

        result = self._coll.replace_one({'_id': state.obj_id, 'state': _state_val}, state.to_dict(), upsert=True)
        logger.debug(
            f'Grabbed OtherDevice {state} in the db: '
            f'matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}'
        )
        if not result.acknowledged:
            return None
        return state

    def logged_in(self, state: OtherDevice, eppn: str, credentials_used: List[UsedCredential]) -> Optional[OtherDevice]:
        """
        Finish a state, on device 2.
        """
        if state.state != OtherDeviceState.IN_PROGRESS:
            return None

        if not state.device2.ref:
            return None

        if (state.eppn and state.eppn != eppn) or not eppn:
            logger.error(f'Can\'t record use other device as finished for eppn {eppn} (state has eppn {state.eppn})')
            return None

        _state_val = state.state.value
        state.state = OtherDeviceState.LOGGED_IN
        state.eppn = eppn
        state.device2.credentials_used = credentials_used
        state.device2.response_code = make_short_code()

        result = self._coll.replace_one({'_id': state.obj_id, 'state': _state_val}, state.to_dict(), upsert=True)
        logger.debug(
            f'Finished OtherDevice {state} in the db: '
            f'matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}'
        )
        if not result.acknowledged:
            return None
        return state
