from eduid.userdb.credentials import U2F, Webauthn

webauthn_credential = Webauthn.from_dict(
    {
        "keyhandle": "i3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_Q",
        "credential_data": "AAAAAAAAAAAAAAAAAAAAAABAi3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_aUBAgMmIAEhWCCiwDYGxl1LnRMqooWm0aRR9YbBG2LZ84BMNh_4rHkA9yJYIIujMrUOpGekbXjgMQ8M13ZsBD_cROSPB79eGz2Nw1ZE",
        "app_id": "",
        "attest_obj": "bzJObWJYUmtibTl1WldkaGRIUlRkRzEwb0doaGRYUm9SR0YwWVZqRXhvVGI1OVBlcEV0YW9PYWY5RDlOUjIxVWJfSU5PT0tfVDdubDFuZHNIUlJCQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFJdHlvd1U5TGVVejV1dmQwX1R0SC1NOG9zTDNidlhHUEFYb0FvNGxiNnZ4VXZtWmozTDE0cVJieDd3LVFoLW1WVVVkNTdGYkRwV3RBbW5kMzI3VkFQMmxBUUlESmlBQklWZ2dvc0EyQnNaZFM1MFRLcUtGcHRHa1VmV0d3UnRpMmZPQVREWWYtS3g1QVBjaVdDQ0xveksxRHFSbnBHMTQ0REVQRE5kMmJBUV8zRVRrandlX1hoczlqY05XUkE=",
        "description": "unit test webauthn token",
    }
)

u2f_credential = U2F.from_dict(
    {
        "version": "U2F_V2",
        "keyhandle": "V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n_rHFXcXbSpOoX__aUKyTR6jEC8Xv678WjXC5KEkvziA",
        "public_key": "BHVTWuo3_D7ruRBe2Tw-m2atT2IOm_qQWSDreWShu3t21ne9c-DPSUdym-H-t7FcjV7rj1dSc3WSwaOJpFmkKxQ",
        "app_id": "https://eduid.se/u2f-app-id.json",
        "attest_cert": "",
        "description": "unit test U2F token",
    }
)
