# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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
#     3. Neither the name of the SUNET nor the names of its
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
from datetime import datetime

from bson import ObjectId

from eduid.userdb.credentials.password import Password

signup_password = Password(
    credential_id=str(ObjectId('112345678901234567890123')),
    salt='$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
    created_by='signup',
    created_ts=datetime.fromisoformat('2013-09-02T10:23:25'),
)


signup_password_2 = Password(
    credential_id=str(ObjectId('a12345678901234567890123')),
    salt='$NDNv1H1$2d465dcc9c68075aa095b646a98e2e3edb1c612c175ebdeaca6c9a55a0457833$32$32$',
    created_by='signup',
    created_ts=datetime.fromisoformat('2017-01-04T16:47:30'),
)


old_password = Password.from_dict(
    {
        'id': ObjectId('112345678901234567890123'),
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
        'source': 'signup',
        'created_ts': datetime.fromisoformat("2013-09-02T10:23:25"),
    }
)
