#
# Copyright (c) 2014-2015 NORDUnet A/S
# Copyright (c) 2018 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Enrique Perez <enrique@cazalla.net>
#
from __future__ import annotations

from typing import Any, Dict, Optional, Type

from bson import ObjectId
from pydantic import BaseModel, Field


class ActionResult(BaseModel):
    success: bool


class Action(BaseModel):
    """
    Generic eduID action object.
    """

    # eppn: User eppn
    eppn: str
    # action_type: What action to perform
    action_type: str = Field(alias='action')
    # action_id: Unique identifier for the action
    action_id: ObjectId = Field(default_factory=ObjectId, alias='_id')
    # preference: Used to sort actions
    preference: int = 100
    # session: IdP session identifier
    session: str = ''
    # params: Parameters for action
    params: Dict[str, Any] = Field(default={})
    # result: Result of action (return value to IdP typically)
    result: Optional[ActionResult] = None

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True

    def to_dict(self) -> Dict[str, Any]:
        """
        Return action data serialized into a dict that can be stored in MongoDB.
        """
        res = self.dict()

        res['_id'] = res.pop('action_id')
        res['action'] = res.pop('action_type')

        if res['session'] == '':
            del res['session']

        return res

    @classmethod
    def from_dict(cls: Type[Action], data: Dict[str, Any]) -> Action:
        """
        Reconstruct Action object from data retrieved from the db
        """
        return cls(**data)
