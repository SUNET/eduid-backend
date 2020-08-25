from datetime import datetime, timedelta
from unittest import TestCase
from uuid import uuid4

from eduid_userdb.signup import Invite, InviteMailAddress, InviteType, SCIMReference


class TestSignupInvite(TestCase):
    def test_scim_invite(self):
        invite = Invite(
            invite_type=InviteType.SCIM,
            invite_reference=SCIMReference(data_owner='test_data_owner', scim_id=uuid4()),
            invite_code='test_invite_code',
            display_name='Testaren Test Testsson',
            given_name='Testaren',
            surname='Testsson',
            mail_addresses=[InviteMailAddress(email='johnsmith@example.com', primary=True)],
            send_email=True,
            finish_url='https://example.com/finish',
            completed=False,
            expires_at=datetime.utcnow() + timedelta(days=180),
        )
        invite_dict = invite.to_dict()
        assert invite == Invite.from_dict(invite_dict)
