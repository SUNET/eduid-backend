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

from eduid.userdb.orcid import Orcid

dashboard_orcid = Orcid.from_dict(
    {
        "id": "https://op.example.org/user_orcid",
        "oidc_authz": {
            "access_token": "b8b8ca5d-b233-4d49-830a-ede934c626d3",
            "token_type": "bearer",
            "id_token": {
                "iss": "https://op.example.org",
                "sub": "subject_identifier",
                "aud": ["APP_ID"],
                "exp": 1526392540,
                "iat": 1526391940,
                "created_by": "test",
                "nonce": "a_nonce_token",
                "auth_time": 1526389879,
            },
            "created_by": "test",
            "expires_in": 631138518,
            "refresh_token": "a110e7d2-4968-42d4-a91d-f379b55a0e60",
        },
        "created_by": "test",
        "created_ts": datetime.fromisoformat("2020-09-02T10:23:25"),
        "modified_ts": datetime.fromisoformat("2020-09-07T14:25:12"),
        "verified": True,
        "name": "Test Testsson",
    }
)
