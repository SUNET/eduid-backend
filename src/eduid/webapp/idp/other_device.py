from __future__ import annotations

import logging
import os
import typing
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Optional, Type

from bson import ObjectId
from flask import request
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.db import BaseDB
from eduid.userdb.element import ElementKey
from eduid.webapp.idp.assurance_data import EduidAuthnContextClass
from eduid.webapp.idp.other_device_data import OtherDeviceId, OtherDeviceState

if typing.TYPE_CHECKING:
    from eduid.webapp.common.session.logindata import LoginContext

logger = logging.getLogger(__name__)


class OtherDevice(BaseModel):
    state_id: OtherDeviceId  # unique reference for this state
    state: OtherDeviceState  # the state this request is in
    short_code: str = Field(repr=False)  # short code perhaps shown to user on device 1, this is a secret value
    eppn: Optional[str]  # the eppn of the user on device 1, either from the SSO session or entered e-mail address
    login_ref: str  # the login 'ref' on device 1 (where login using another device was initiated)
    authn_context: Optional[EduidAuthnContextClass]  # the level of authentication required on device 1
    request_id: Optional[str]  # the request ID on device 1 (SAML authnRequest request id for example)
    reauthn_required: bool  # if reauthn is required for the login on device 1
    ip_address: str  # the IP address of device 1, to be used by the user on device 2 to assess the request
    user_agent: Optional[str]  # the user agent of device 1, to be used by the user on device 2 to assess the request
    created_at: datetime
    expires_at: datetime
    obj_id: ObjectId = Field(default_factory=ObjectId, alias='_id')
    response_code: Optional[str] = None  # code from login event (using device 2) that has to be entered on device 1
    bad_attempts: int = 0  # number of failed attempts to produce the right response_code
    # TODO: doesn't work with onetime_credentials
    credentials_used: Dict[ElementKey, datetime] = Field(default={})

    class Config:
        # Don't reject ObjectId
        arbitrary_types_allowed = True

    @classmethod
    def from_parameters(
        cls: Type[OtherDevice],
        eppn: Optional[str],
        login_ref: str,
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
            login_ref=login_ref,
            authn_context=authn_context,
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            reauthn_required=reauthn_required,
            created_at=now,
            expires_at=now + ttl,
        )

    def to_dict(self) -> Mapping[str, Any]:
        return self.dict()

    @classmethod
    def from_dict(cls: Type[OtherDevice], data: Mapping[str, Any]) -> OtherDevice:
        return cls(**data)


def make_short_code() -> str:
    digits = int.from_bytes(os.urandom(4), byteorder='big') % 1000000
    return '{:06d}'.format(digits)


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
        from eduid.webapp.idp.assurance import get_requested_authn_context

        authn_ref = get_requested_authn_context(ticket)
        state = OtherDevice.from_parameters(
            eppn=None if not user else user.eppn,
            login_ref=ticket.request_ref,
            authn_context=authn_ref,
            request_id=ticket.request_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('user-agent'),
            ttl=ttl,
        )
        res = self.save(state)
        logger.debug(f'Save {state} result: {res}')
        logger.info(f'Created other-device state: {state.state_id}')
        logger.debug(f'   Full other-device state: {state}')
        return state
