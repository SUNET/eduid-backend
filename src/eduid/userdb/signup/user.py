#
# Copyright (c) 2015 NORDUnet A/S
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

__author__ = 'ft'

from typing import Any, Dict, Optional

import bson
from pydantic import Field

from eduid.userdb.proofing import EmailProofingElement
from eduid.userdb.user import User


class SignupUser(User):
    """
    Subclass of eduid.userdb.User with eduid Signup application specific data.
    """

    social_network: Optional[str] = None
    social_network_id: Optional[str] = None
    # The user's pending (unconfirmed) mail address.
    pending_mail_address: Optional[EmailProofingElement] = None
    # Holds a reference id that is used for connecting msg tasks with proofing log statements.
    proofing_reference: str = Field(default_factory=lambda: str(bson.ObjectId()))

    @classmethod
    def check_or_use_data(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        _social_network = data.pop('social_network', None)
        _social_network_id = data.pop('social_network_id', None)
        _pending_mail_address = data.pop('pending_mail_address', None)
        _proofing_reference = data.pop('proofing_reference', None)
        if _pending_mail_address:
            if isinstance(_pending_mail_address, dict):
                _pending_mail_address = EmailProofingElement.from_dict(_pending_mail_address)

        data['social_network'] = _social_network
        data['social_network_id'] = _social_network_id
        data['pending_mail_address'] = _pending_mail_address
        if _proofing_reference:
            data['proofing_reference'] = _proofing_reference

        return data

    def to_dict(self) -> Dict[str, Any]:
        res = User.to_dict(self)
        if self.pending_mail_address is not None:
            res['pending_mail_address'] = self.pending_mail_address.to_dict()
        return res
