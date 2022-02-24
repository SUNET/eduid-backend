from __future__ import annotations

import json
import logging
import typing
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Optional, Type
from uuid import uuid4

import nacl
import nacl.encoding
import nacl.secret
import nacl.utils
from bson import ObjectId
from nacl.secret import SecretBox
from pydantic import BaseModel, Field

from eduid.userdb.db import BaseDB
from eduid.userdb.util import utc_now

logger = logging.getLogger(__name__)

KnownDeviceId = typing.NewType('KnownDeviceId', str)


class BrowserDeviceInfo(BaseModel):
    shared: str  # encrypted and formatted for sharing with the eduID frontend (will be stored in browser local storage)
    state_id: KnownDeviceId  # database id for this device
    secret_box: SecretBox  # nacl secretbox to encrypt/decrypt database contents for this device

    class Config:
        arbitrary_types_allowed = True  # don't reject SecretBox

    def __str__(self):
        # Ensure no more than necessary of the public (really 'shared with browser') and state_id end up in logs etc.
        return f'<{self.__class__.__name__}: public[8]={repr(self.shared[:8])}, state_id[8]={repr(self.state_id[:8])}>'

    @classmethod
    def from_public(cls: Type[BrowserDeviceInfo], shared: str, app_secret_box: SecretBox) -> BrowserDeviceInfo:
        _data: bytes = app_secret_box.decrypt(shared, encoder=nacl.encoding.URLSafeBase64Encoder)
        if not _data.startswith(b'1|'):
            raise ValueError('Unhandled browser device info')

        # version 1 format is 1|state_id_str|private_key_b64
        _v, state_id, private_key_str = _data.decode().split('|')
        secret_box = SecretBox(nacl.encoding.Base64Encoder.decode(private_key_str))
        return cls(shared=shared, state_id=state_id, secret_box=secret_box)

    @classmethod
    def new(cls: Type[BrowserDeviceInfo], app_secret_box: SecretBox) -> BrowserDeviceInfo:
        state_id = str(uuid4())
        private_key_bytes = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        secret_box = SecretBox(private_key_bytes)
        # version 1 format is 1|state_id_str|private_key_b64
        versioned = '|'.join(['1', state_id, nacl.encoding.Base64Encoder.encode(private_key_bytes).decode()])
        shared = app_secret_box.encrypt(versioned.encode(), encoder=nacl.encoding.URLSafeBase64Encoder)
        return cls(shared=shared, state_id=KnownDeviceId(state_id), secret_box=secret_box)


class KnownDeviceData(BaseModel):
    eppn: Optional[str] = None
    last_login: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def to_json(self):
        return self.json(exclude_none=True)


class KnownDevice(BaseModel):
    state_id: KnownDeviceId
    obj_id: ObjectId = Field(default_factory=ObjectId, alias='_id')
    data: KnownDeviceData = Field(default_factory=KnownDeviceData)
    expires_at: datetime = Field(default_factory=utc_now)
    last_used: datetime = Field(default_factory=utc_now)

    class Config:
        # Don't reject ObjectId and SecretBox
        arbitrary_types_allowed = True

    def to_dict(self, from_browser: BrowserDeviceInfo) -> Dict[str, Any]:
        res = self.dict()
        res['_id'] = res.pop('obj_id')
        res['data'] = from_browser.secret_box.encrypt(self.data.to_json().encode(), encoder=nacl.encoding.Base64Encoder)
        return res

    @classmethod
    def from_dict(cls: Type[KnownDevice], data: Mapping[str, Any], from_browser: BrowserDeviceInfo) -> KnownDevice:
        _data = dict(data)  # don't modify callers data
        _data['data'] = json.loads(from_browser.secret_box.decrypt(_data['data'], encoder=nacl.encoding.Base64Encoder))
        return cls(**_data)


class KnownDeviceDB(BaseDB):
    def __init__(
        self,
        db_uri: str,
        app_secretbox_key: str,
        new_ttl: timedelta,
        ttl: timedelta,
        db_name: str = 'eduid_idp',
        collection: str = 'known_device',
    ):
        super().__init__(db_uri, db_name, collection=collection)

        self._new_ttl = new_ttl
        self._ttl = ttl
        self._app_secret_box = SecretBox(nacl.encoding.URLSafeBase64Encoder.decode(app_secretbox_key))

        indexes = {
            'auto-discard': {'key': [('expires_at', 1)], 'expireAfterSeconds': 0},
            'unique-state-id': {'key': [('state_id', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def save(self, state: KnownDevice, from_browser: BrowserDeviceInfo, ttl: Optional[timedelta] = None) -> bool:
        """
        Add a new KnownDevice to the database, or update an existing one.
        """
        if ttl is not None:
            state.expires_at = utc_now() + ttl

        result = self._coll.replace_one({'_id': state.obj_id}, state.to_dict(from_browser=from_browser), upsert=True)
        logger.debug(
            f'Saved KnownDevice {state} in the db: '
            f'matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}'
        )
        return result.acknowledged

    def get_state_by_browser_info(self, from_browser: BrowserDeviceInfo) -> Optional[KnownDevice]:
        state = self._get_document_by_attr('state_id', from_browser.state_id)
        if not state:
            logger.debug(f'Known-device state with state_id {from_browser.state_id} not found in the database')
            return None
        return KnownDevice.from_dict(state, from_browser=from_browser)

    def create_new_state(self) -> BrowserDeviceInfo:
        browser_info = BrowserDeviceInfo.new(app_secret_box=self._app_secret_box)
        state = KnownDevice(state_id=browser_info.state_id)
        if not self.save(state, from_browser=browser_info, ttl=self._new_ttl):
            raise RuntimeError('Failed saving known device to database')
        return browser_info
