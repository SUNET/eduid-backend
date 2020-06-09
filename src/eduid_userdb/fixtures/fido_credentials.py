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
from eduid_userdb.credentials import Webauthn, U2F


webauthn_credential = Webauthn(
    keyhandle='i3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_Q',
    credential_data='AAAAAAAAAAAAAAAAAAAAAABAi3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_aUBAgMmIAEhWCCiwDYGxl1LnRMqooWm0aRR9YbBG2LZ84BMNh_4rHkA9yJYIIujMrUOpGekbXjgMQ8M13ZsBD_cROSPB79eGz2Nw1ZE',
    app_id='',
    attest_obj='bzJObWJYUmtibTl1WldkaGRIUlRkRzEwb0doaGRYUm9SR0YwWVZqRXhvVGI1OVBlcEV0YW9PYWY5RDlOUjIxVWJfSU5PT0tfVDdubDFuZHNIUlJCQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFJdHlvd1U5TGVVejV1dmQwX1R0SC1NOG9zTDNidlhHUEFYb0FvNGxiNnZ4VXZtWmozTDE0cVJieDd3LVFoLW1WVVVkNTdGYkRwV3RBbW5kMzI3VkFQMmxBUUlESmlBQklWZ2dvc0EyQnNaZFM1MFRLcUtGcHRHa1VmV0d3UnRpMmZPQVREWWYtS3g1QVBjaVdDQ0xveksxRHFSbnBHMTQ0REVQRE5kMmJBUV8zRVRrandlX1hoczlqY05XUkE=',
    description='unit test webauthn token'
)

u2f_credential = U2F(
    version='U2F_V2',
    keyhandle='V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n_rHFXcXbSpOoX__aUKyTR6jEC8Xv678WjXC5KEkvziA',
    public_key='BHVTWuo3_D7ruRBe2Tw-m2atT2IOm_qQWSDreWShu3t21ne9c-DPSUdym-H-t7FcjV7rj1dSc3WSwaOJpFmkKxQ',
    app_id='https://eduid.se/u2f-app-id.json',
    attest_cert='',
    description='unit test U2F token',
)
