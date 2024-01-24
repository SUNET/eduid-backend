from datetime import datetime

from eduid.userdb.proofing import EmailProofingElement

johnsmith2_example_com_pending = EmailProofingElement(
    email="johnsmith2@example.com",
    created_by="dashboard",
    created_ts=datetime.fromisoformat("2013-09-02T10:23:25"),
    is_verified=False,
)
