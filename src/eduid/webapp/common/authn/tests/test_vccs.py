from collections.abc import Iterator
from datetime import timedelta
from typing import Any, NoReturn, cast

import pytest
from pytest_mock import MockerFixture

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.password import Password
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.testing import MongoTestCase
from eduid.userdb.user import User
from eduid.vccs.client import VCCSClient, VCCSClientHTTPError
from eduid.webapp.common.authn import vccs as vccs_module
from eduid.webapp.common.authn.testing import MockVCCSClient
from eduid.webapp.common.authn.vccs import CheckPasswordResult


class VCCSTestCase(MongoTestCase):
    user: User

    @pytest.fixture(autouse=True)
    def setup(self, setup_mongo: None) -> Iterator[None]:
        self.amdb.save(UserFixtures().new_user_example)
        self.vccs_client = cast(VCCSClient, MockVCCSClient())
        _user = self.amdb.get_user_by_mail("johnsmith@example.com")
        assert _user is not None
        self.user = _user

        # Start with no credentials
        for credential in self.user.credentials.to_list():
            self.user.credentials.remove(credential.key)
        vccs_module.add_password(self.user, new_password="abcd", application="test", vccs=self.vccs_client)

        yield

        vccs_module.revoke_passwords(self.user, reason="testing", application="test", vccs=self.vccs_client)

    def _check_credentials(self, creds: str, upgrade_v2: bool = False) -> CheckPasswordResult | None:
        return vccs_module.check_password(
            creds, self.user, vccs=self.vccs_client, upgrade_v2=upgrade_v2, application="test"
        )

    def test_check_good_credentials(self) -> None:
        result = self._check_credentials("abcd")
        assert result is not None
        assert result.success

    def test_check_bad_credentials(self) -> None:
        result = self._check_credentials("fghi")
        assert result is None

    def test_add_password(self) -> None:
        added = vccs_module.add_password(self.user, new_password="wxyz", application="test", vccs=self.vccs_client)
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is not None
        assert result1.success
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success
        assert not result3.password.is_generated

    def test_add_password_generated(self) -> None:
        added = vccs_module.add_password(
            self.user, new_password="wxyz", is_generated=True, application="test", vccs=self.vccs_client
        )
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is not None
        assert result1.success
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success
        assert result3.password.is_generated

    def test_change_password(self) -> None:
        added = vccs_module.change_password(
            self.user, new_password="wxyz", old_password="abcd", application="test", vccs=self.vccs_client
        )
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is None
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success
        assert not result3.password.is_generated

    def test_change_password_generated(self) -> None:
        added = vccs_module.change_password(
            self.user,
            new_password="wxyz",
            old_password="abcd",
            application="test",
            is_generated=True,
            vccs=self.vccs_client,
        )
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is None
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success
        assert result3.password.is_generated

    def test_change_password_bad_old_password(self) -> None:
        added = vccs_module.change_password(
            self.user, new_password="wxyz", old_password="fghi", application="test", vccs=self.vccs_client
        )
        assert not added
        result1 = self._check_credentials("abcd")
        assert result1 is not None
        assert result1.success
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is None

    def test_reset_password(self) -> None:
        added = vccs_module.reset_password(self.user, new_password="wxyz", application="test", vccs=self.vccs_client)
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is None
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success
        assert not result3.password.is_generated

    def test_reset_password_generated(self) -> None:
        added = vccs_module.reset_password(
            self.user, new_password="wxyz", application="test", is_generated=True, vccs=self.vccs_client
        )
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is None
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success
        assert result3.password.is_generated

    def test_change_password_error_adding(self, mocker: MockerFixture) -> None:
        from eduid.webapp.common.authn.testing import MockVCCSClient

        mock_add = mocker.patch.object(MockVCCSClient, "add_credentials")
        mock_add.return_value = False
        added = vccs_module.change_password(
            self.user, new_password="wxyz", old_password="abcd", application="test", vccs=self.vccs_client
        )
        assert not added
        result1 = self._check_credentials("abcd")
        assert result1 is None
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is None

    def test_reset_password_error_revoking(self, mocker: MockerFixture) -> None:
        from eduid.webapp.common.authn.testing import MockVCCSClient

        def mock_revoke_creds(*args: Any) -> NoReturn:
            raise VCCSClientHTTPError("dummy", 500)

        mocker.patch.object(MockVCCSClient, "revoke_credentials", mock_revoke_creds)
        added = vccs_module.reset_password(self.user, new_password="wxyz", application="test", vccs=self.vccs_client)
        assert added
        result1 = self._check_credentials("abcd")
        assert result1 is None
        result2 = self._check_credentials("fghi")
        assert result2 is None
        result3 = self._check_credentials("wxyz")
        assert result3 is not None
        assert result3.success

    def test_upgrade_password_to_v2(self) -> None:
        """Test that upgrade_password_to_v2 creates a v2 credential alongside the existing v1."""
        # Get the current v1 password
        v1_passwords = list(self.user.credentials.filter(Password))
        assert len(v1_passwords) == 1
        v1_password = v1_passwords[0]
        assert v1_password.version == 1

        # Upgrade to v2
        result = vccs_module.upgrade_password_to_v2(
            user=self.user,
            password="abcd",
            old_credential=v1_password,
            application="test",
            vccs=self.vccs_client,
        )
        assert result

        # Should now have both v1 and v2 credentials
        all_passwords = list(self.user.credentials.filter(Password))
        assert len(all_passwords) == 2

        versions = {p.version for p in all_passwords}
        assert versions == {1, 2}

        # Credential IDs should be different
        credential_ids = {p.credential_id for p in all_passwords}
        assert len(credential_ids) == 2

    def test_check_password_triggers_upgrade(self) -> None:
        """Test that check_password triggers v1->v2 upgrade when upgrade_v2=True."""
        # Verify we start with only v1
        passwords = list(self.user.credentials.filter(Password))
        assert len(passwords) == 1
        assert passwords[0].version == 1

        # Check password with upgrade enabled
        result = vccs_module.check_password(
            "abcd", self.user, vccs=self.vccs_client, upgrade_v2=True, application="test"
        )
        assert result is not None
        assert result.success
        assert result.credentials_changed

        # Should now have both v1 and v2
        all_passwords = list(self.user.credentials.filter(Password))
        assert len(all_passwords) == 2
        versions = {p.version for p in all_passwords}
        assert versions == {1, 2}

    def test_check_password_no_upgrade_when_disabled(self) -> None:
        """Test that no upgrade happens when upgrade_v2=False (default)."""
        passwords_before = list(self.user.credentials.filter(Password))
        assert len(passwords_before) == 1

        result = vccs_module.check_password("abcd", self.user, vccs=self.vccs_client)
        assert result is not None
        assert result.success
        assert not result.credentials_changed

        # Should still have only v1
        passwords_after = list(self.user.credentials.filter(Password))
        assert len(passwords_after) == 1
        assert passwords_after[0].version == 1

    def test_check_password_no_double_upgrade(self) -> None:
        """Test that a second auth with upgrade_v2=True doesn't create a duplicate v2."""
        # First auth triggers upgrade
        result1 = vccs_module.check_password(
            "abcd", self.user, vccs=self.vccs_client, upgrade_v2=True, application="test"
        )
        assert result1 is not None
        passwords_after_first = list(self.user.credentials.filter(Password))
        assert len(passwords_after_first) == 2

        # Second auth should NOT create another v2
        result2 = vccs_module.check_password(
            "abcd", self.user, vccs=self.vccs_client, upgrade_v2=True, application="test"
        )
        assert result2 is not None
        passwords_after_second = list(self.user.credentials.filter(Password))
        assert len(passwords_after_second) == 2

    def test_check_password_upgrade_failure(self, mocker: MockerFixture) -> None:
        """Test that auth still succeeds when v2 upgrade fails."""
        from eduid.webapp.common.authn.testing import MockVCCSClient

        # Verify we start with only v1
        passwords_before = list(self.user.credentials.filter(Password))
        assert len(passwords_before) == 1
        assert passwords_before[0].version == 1

        mock_add = mocker.patch.object(MockVCCSClient, "add_credentials")
        mock_add.return_value = False

        result = vccs_module.check_password(
            "abcd", self.user, vccs=self.vccs_client, upgrade_v2=True, application="test"
        )

        # Auth should still succeed with v1
        assert result is not None
        assert result.password.version == 1

        # No v2 should have been added
        passwords_after = list(self.user.credentials.filter(Password))
        assert len(passwords_after) == 1
        assert passwords_after[0].version == 1

    def test_check_password_v2_preferred(self) -> None:
        """Test that v2 credential is returned when both v1 and v2 exist and upgrade_v2 is True."""
        # Add a v1 password and upgrade it
        v1_passwords = list(self.user.credentials.filter(Password))
        assert len(v1_passwords) == 1
        v1_password = v1_passwords[0]

        vccs_module.upgrade_password_to_v2(
            user=self.user,
            password="abcd",
            old_credential=v1_password,
            application="test",
            vccs=self.vccs_client,
        )

        # Now check_password should return the v2 credential when upgrade_v2=True
        result = vccs_module.check_password("abcd", self.user, vccs=self.vccs_client, upgrade_v2=True)
        assert result is not None
        assert result.password.version == 2

    def test_grace_period_revocation(self) -> None:
        """Test that v1 is revoked after grace period (counted from v2 creation) when v2 exists."""
        from datetime import timedelta

        from eduid.common.misc.timeutil import utc_now

        # Create a v2 credential
        vccs_module.check_password(
            "abcd",
            self.user,
            vccs=self.vccs_client,
            upgrade_v2=True,
            application="test",
        )

        # Simulate v2 being created long ago (grace period is measured from v2 creation)
        v2_passwords = [p for p in self.user.credentials.filter(Password) if p.version == 2]
        assert len(v2_passwords) == 1
        v2_passwords[0].created_ts = utc_now() - timedelta(days=100)

        # Authenticate again with grace_period=90 days - v1 should be revoked
        # because v2 was created 100 days ago, exceeding the 90-day grace period
        result = vccs_module.check_password(
            "abcd",
            self.user,
            vccs=self.vccs_client,
            upgrade_v2=True,
            application="test",
            revoke_v1_grace_period=timedelta(days=90),
        )
        assert result is not None
        assert result.success
        assert result.credentials_changed
        assert result.password.version == 2

        # v1 should be revoked
        v1_after = [p for p in self.user.credentials.filter(Password) if p.version == 1]
        assert len(v1_after) == 0

    def test_grace_period_no_revocation_within_period(self) -> None:
        """Test that v1 is NOT revoked within grace period."""
        # Create a v2 credential
        vccs_module.check_password(
            "abcd",
            self.user,
            vccs=self.vccs_client,
            upgrade_v2=True,
            application="test",
        )

        # v2 is recent (just created), grace_period=90 days
        result = vccs_module.check_password(
            "abcd",
            self.user,
            vccs=self.vccs_client,
            revoke_v1_grace_period=timedelta(days=90),
        )
        assert result is not None
        assert result.success
        assert not result.credentials_changed

        # v1 should still exist
        v1_after = [p for p in self.user.credentials.filter(Password) if p.version == 1]
        assert len(v1_after) == 1

    def test_change_password_after_v2_upgrade(self) -> None:
        """Test password change after v1->v2 upgrade.

        After upgrade, both v1 and v2 exist. change_password authenticates with v2 (preferred)
        and only revokes the matched credential. This leaves the v1 credential behind, so the
        old password still works via v1.
        """
        # Start with v1 password "abcd"
        passwords = list(self.user.credentials.filter(Password))
        assert len(passwords) == 1
        assert passwords[0].version == 1

        # Upgrade to v2 (both v1 and v2 now exist for "abcd")
        result = self._check_credentials("abcd", upgrade_v2=True)
        assert result is not None
        assert result.success
        assert result.credentials_changed
        passwords = list(self.user.credentials.filter(Password))
        assert len(passwords) == 2
        assert {p.version for p in passwords} == {1, 2}

        # Change password from "abcd" to "wxyz" with version=2
        # and if we are within the grace period a v1 version will also be added
        changed = vccs_module.change_password(
            self.user,
            new_password="wxyz",
            old_password="abcd",
            application="test",
            vccs=self.vccs_client,
            version=2,
            password_v2_grace_period=timedelta(days=180),
        )
        assert changed is True

        # change_password revokes both v1 and v2 version of the old password
        # if we are within the grace period both versions should be there
        passwords_after = list(self.user.credentials.filter(Password))
        assert len(passwords_after) == 2
        versions_after = {p.version for p in passwords_after}
        assert versions_after == {1, 2}

        # New password "wxyz" works and is v1
        # mock v2 ignorance
        self.vccs_client.allow_v2 = False  # type: ignore[attr-defined]
        result_new = self._check_credentials("wxyz")
        assert result_new is not None
        assert result_new.success
        assert result_new.password.version == 1
        # reset v2
        self.vccs_client.allow_v2 = True  # type: ignore[attr-defined]

        # New password "wxyz" works and is v2
        result_new = self._check_credentials("wxyz", upgrade_v2=True)
        assert result_new is not None
        assert result_new.success
        assert result_new.password.version == 2

        # Old password "abcd" does no longer work
        result_old = self._check_credentials("abcd")
        assert result_old is None
        result_old = self._check_credentials("abcd", upgrade_v2=True)
        assert result_old is None

    def test_change_password_after_v2_upgrade_outside_grace_period(self) -> None:
        """Test password change after v1->v2 upgrade.

        After upgrade, both v1 and v2 exist. change_password authenticates with v2 (preferred)
        and only revokes the matched credential. This leaves the v1 credential behind, so the
        old password still works via v1.
        """
        # Start with v1 password "abcd"
        passwords = list(self.user.credentials.filter(Password))
        assert len(passwords) == 1
        assert passwords[0].version == 1

        # Upgrade to v2 (both v1 and v2 now exist for "abcd")
        result = self._check_credentials("abcd", upgrade_v2=True)
        assert result is not None
        assert result.success
        assert result.credentials_changed
        passwords = list(self.user.credentials.filter(Password))
        assert len(passwords) == 2
        assert {p.version for p in passwords} == {1, 2}

        # Simulate v2 being created long ago (outside grace period)
        v2_passwords = [p for p in self.user.credentials.filter(Password) if p.version == 2]
        assert len(v2_passwords) == 1
        v2_passwords[0].created_ts = utc_now() - timedelta(days=200)

        # Change password from "abcd" to "wxyz" with version=2
        # no version=1 password will be added outside grace period
        changed = vccs_module.change_password(
            self.user,
            new_password="wxyz",
            old_password="abcd",
            application="test",
            vccs=self.vccs_client,
            version=2,
            password_v2_grace_period=timedelta(days=180),
        )
        assert changed is True

        # change_password revokes both v1 and v2 version of the old password
        passwords_after = list(self.user.credentials.filter(Password))
        assert len(passwords_after) == 1
        versions_after = {p.version for p in passwords_after}
        assert versions_after == {2}

        # New password "wxyz" works and is v2
        result_new = self._check_credentials("wxyz", upgrade_v2=True)
        assert result_new is not None
        assert result_new.success
        assert result_new.password.version == 2

        # New password "wxyz" v1 does not work
        # mock v2 ignorance
        self.vccs_client.allow_v2 = False  # type: ignore[attr-defined]
        result_new = self._check_credentials("wxyz")
        assert result_new is None
        # reset v2
        self.vccs_client.allow_v2 = True  # type: ignore[attr-defined]

        # Old password "abcd" does no longer work
        result_old = self._check_credentials("abcd")
        assert result_old is None
