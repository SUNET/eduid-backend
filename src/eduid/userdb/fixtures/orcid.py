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
