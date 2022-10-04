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

from eduid.userdb.phone import PhoneNumber

dashboard_primary_phone = PhoneNumber.from_dict(
    {
        "number": "+34609609609",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified": True,
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": True,
    }
)


dashboard_verified_phone = PhoneNumber.from_dict(
    {
        "number": "+34607507507",
        "verified": True,
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified_by": "dashboard",
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
    }
)


dashboard_unverified_phone = PhoneNumber.from_dict(
    {
        "number": "+34 6096096096",
        "created_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "created_by": "dashboard",
        "verified": False,
        "verified_ts": datetime.fromisoformat("2013-09-02T10:23:25"),
        "primary": False,
    }
)


old_primary_phone = PhoneNumber.from_dict({"mobile": "+34609609609", "primary": True, "verified": True})


old_unverified_phone = PhoneNumber.from_dict({"mobile": "+34 6096096096", "verified": False})
