#!/usr/bin/python


import datetime
import logging
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from bson import ObjectId

import eduid.userdb
import eduid.webapp.common.authn
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.password import Password
from eduid.userdb.idp.credential_user import CredentialUser
from eduid.userdb.mail import MailAddress
from eduid.vccs.client import VCCSClient, VCCSPasswordFactor
from eduid.webapp.common.api import exceptions
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.idp.idp_authn import IdPAuthn
from eduid.webapp.idp.tests.test_api import IdPAPITests

logger = logging.getLogger(__name__)

eduid.webapp.common.authn.TESTING = True


class TestIdPUserDb(IdPAPITests):
    def test_lookup_user_by_email(self) -> None:
        assert self.test_user.mail_addresses.primary
        _this = self.app.userdb.lookup_user(self.test_user.mail_addresses.primary.email)
        assert _this
        assert _this.eppn == self.test_user.eppn

    def test_lookup_user_by_eppn(self) -> None:
        _this = self.app.userdb.lookup_user(self.test_user.eppn)
        assert _this
        assert _this.eppn == self.test_user.eppn

    def test_password_authn(self) -> None:
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate"):
            VCCSClient.authenticate.return_value = True  # type: ignore[attr-defined]
            assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
            assert self.test_user.mail_addresses.primary
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
            assert pwauth
            assert pwauth.user.eppn == self.test_user.eppn
            assert pwauth.authn_data is not None

    def test_verify_username_and_incorrect_password(self) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = False
            assert self.test_user.mail_addresses.primary
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
            assert pwauth is None


class TestAuthentication(IdPAPITests):
    def test_authn_unknown_user(self) -> None:
        assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
        pwauth = self.app.authn.password_authn("foo", "bar")
        assert pwauth is None

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_authn_known_user_wrong_password(
        self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock
    ) -> None:
        mock_add_credentials.return_value = False
        mock_authenticate.return_value = False
        assert isinstance(self.test_user, eduid.userdb.User)
        assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
        cred_id = ObjectId()
        factor = VCCSPasswordFactor("foo", str(cred_id), salt=None)
        self.app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        assert isinstance(self.test_user.mail_addresses.primary, MailAddress)
        pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "bar")
        assert pwauth is None

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_authn_known_user_right_password(
        self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock
    ) -> None:
        mock_add_credentials.return_value = True
        mock_authenticate.return_value = True
        assert isinstance(self.test_user, eduid.userdb.User)
        assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
        passwords = self.test_user.credentials.to_list()
        assert isinstance(passwords[0], Password)
        factor = VCCSPasswordFactor("foo", str(passwords[0].key), salt=passwords[0].salt)
        self.app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        assert isinstance(self.test_user.mail_addresses.primary, MailAddress)
        pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        assert pwauth is not None
        assert pwauth.user.eppn == self.test_user.eppn
        assert pwauth.authn_data is not None
        assert pwauth.authn_data.cred_id == factor.credential_id

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_authn_expired_credential(self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock) -> None:
        mock_add_credentials.return_value = False
        mock_authenticate.return_value = True
        assert isinstance(self.test_user, eduid.userdb.User)
        assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
        passwords = self.test_user.credentials.to_list()
        assert isinstance(passwords[0], Password)
        factor = VCCSPasswordFactor("foo", str(passwords[0].key), salt=passwords[0].salt)
        self.app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        # Store a successful authentication using this credential three year ago
        three_years_ago = utc_now() - datetime.timedelta(days=3 * 365)
        self.app.authn.authn_store.credential_success([passwords[0].key], three_years_ago)
        assert self.test_user.mail_addresses.primary is not None
        with pytest.raises(exceptions.EduidForbidden):
            self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        # Do the same thing again to make sure we didn't accidentally update the
        # 'last successful login' timestamp when it was a successful login with an
        # expired credential.
        with pytest.raises(exceptions.EduidForbidden):
            self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")


class TestPasswordV2Upgrade(IdPAPITests):
    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
        config["password_v2_upgrade_enabled"] = True
        return config

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_v2_upgrade_on_v1_authn(self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock) -> None:
        """Verify that authenticating with a v1 password triggers a v2 upgrade."""
        mock_add_credentials.return_value = True
        mock_authenticate.return_value = True
        assert isinstance(self.app.authn, IdPAuthn)

        # Verify test user has only v1 password credentials
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None
        pw_creds = user.credentials.filter(Password)
        assert len(pw_creds) > 0
        assert all(p.version == 1 for p in pw_creds)

        # Authenticate with the v1 password
        assert self.test_user.mail_addresses.primary
        with self.app.app_context():
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        assert pwauth is not None
        assert pwauth.user.eppn == self.test_user.eppn

        # Verify that credentials_changed is set
        assert pwauth.credentials_changed is True

        # Verify that a v2 credential was created on the user object
        v2_creds = [p for p in pwauth.user.credentials.filter(Password) if p.version == 2]
        assert len(v2_creds) == 1, f"Expected 1 v2 credential, got {len(v2_creds)}"
        assert v2_creds[0].created_by == "idp"

        # Verify add_credentials was called (once for the v2 upgrade)
        mock_add_credentials.assert_called_once()

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_v2_upgrade_skipped_when_v2_exists(
        self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock
    ) -> None:
        """Verify that no upgrade happens if user already has a v2 password."""
        mock_add_credentials.return_value = True
        mock_authenticate.return_value = True
        assert isinstance(self.app.authn, IdPAuthn)

        # Add an existing v2 credential to the user
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None
        v2_password = Password(
            credential_id=str(ObjectId()),
            salt="$NDNv1H1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$32$32$",
            is_generated=False,
            created_by="test",
            version=2,
        )
        user.credentials.add(v2_password)
        self.app.userdb.save(user)

        # Authenticate with the v1 password
        assert self.test_user.mail_addresses.primary
        pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        assert pwauth is not None

        # No credentials should have changed
        assert pwauth.credentials_changed is False

        # add_credentials should NOT have been called (no upgrade needed)
        mock_add_credentials.assert_not_called()

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    def test_v2_upgrade_not_triggered_when_disabled(self, mock_authenticate: MagicMock) -> None:
        """Verify upgrade does not happen when feature flag is disabled."""
        mock_authenticate.return_value = True
        assert isinstance(self.app.authn, IdPAuthn)

        # Disable the feature flag
        self.app.conf.password_v2_upgrade_enabled = False

        assert self.test_user.mail_addresses.primary
        with patch.object(VCCSClient, "add_credentials") as mock_add:
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
            assert pwauth is not None
            assert pwauth.credentials_changed is False
            # add_credentials should NOT have been called
            mock_add.assert_not_called()

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_v2_upgrade_persisted_to_db(
        self,
        mock_add_credentials: MagicMock,
        mock_authenticate: MagicMock,
        mock_request_user_sync: MagicMock,
    ) -> None:
        """Verify that a v2 upgrade is persisted to the database via save_and_sync_user."""
        mock_add_credentials.return_value = True
        mock_authenticate.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        assert isinstance(self.app.authn, IdPAuthn)

        with self.app.app_context():
            # Authenticate with the v1 password -- triggers v2 upgrade
            assert self.test_user.mail_addresses.primary
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
            assert pwauth is not None
            assert pwauth.credentials_changed is True

            # Simulate the save logic from the pw_auth view
            credential_user = CredentialUser.from_user(pwauth.user, self.app.credential_db)
            save_and_sync_user(
                credential_user,
                private_userdb=self.app.credential_db,
                app_name_override="eduid_idp",
            )

            # Verify the v2 credential was saved to the credential_db
            saved_user = self.app.credential_db.get_user_by_eppn(self.test_user.eppn)
            assert saved_user is not None
            v2_creds = [p for p in saved_user.credentials.filter(Password) if p.version == 2]
            assert len(v2_creds) == 1, f"Expected 1 v2 credential in credential_db, got {len(v2_creds)}"

            # Verify the v2 credential was synced to the central userdb
            central_user = self.app.userdb.lookup_user(self.test_user.eppn)
            assert central_user is not None
            central_v2 = [p for p in central_user.credentials.filter(Password) if p.version == 2]
            assert len(central_v2) == 1, f"Expected 1 v2 credential in central userdb, got {len(central_v2)}"

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.revoke_credentials")
    def test_v1_revoked_after_grace_period(
        self, mock_revoke_credentials: MagicMock, mock_authenticate: MagicMock
    ) -> None:
        """Verify that v1 passwords are revoked when authenticating with v2 after the grace period has expired."""
        mock_authenticate.return_value = True
        mock_revoke_credentials.return_value = True
        assert isinstance(self.app.authn, IdPAuthn)

        # Set up user with both v1 and v2 passwords, v2 created well past the grace period
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None

        # Remember the v1 credential
        v1_creds = [p for p in user.credentials.filter(Password) if p.version == 1]
        assert len(v1_creds) == 1, "Test user should have exactly one v1 password"

        # Add a v2 credential created 200 days ago (past default 180-day grace period)
        v2_password = Password(
            credential_id=str(ObjectId()),
            salt="$NDNv1H1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$32$32$",
            is_generated=False,
            created_by="idp",
            version=2,
            created_ts=datetime.datetime.now(tz=datetime.UTC) - timedelta(days=200),
        )
        user.credentials.add(v2_password)
        self.app.userdb.save(user)

        # Authenticate - v2 is preferred, so _upgrade_password gets cred.version==2
        assert self.test_user.mail_addresses.primary
        with self.app.app_context():
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        assert pwauth is not None
        assert pwauth.user.eppn == self.test_user.eppn

        # Verify that credentials_changed is True (v1 was revoked)
        assert pwauth.credentials_changed is True, "credentials_changed should be True after v1 revocation"

        # Verify that the v1 credential was removed from the user object
        remaining_v1 = [p for p in pwauth.user.credentials.filter(Password) if p.version == 1]
        assert len(remaining_v1) == 0, f"Expected 0 v1 credentials after revocation, got {len(remaining_v1)}"

        # Verify that the v2 credential still exists
        remaining_v2 = [p for p in pwauth.user.credentials.filter(Password) if p.version == 2]
        assert len(remaining_v2) == 1, f"Expected 1 v2 credential, got {len(remaining_v2)}"

        # Verify revoke_credentials was called for the v1 password
        mock_revoke_credentials.assert_called_once()
        call_args = mock_revoke_credentials.call_args
        assert str(user.user_id) == call_args[0][0]

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.revoke_credentials")
    def test_v1_not_revoked_within_grace_period(
        self, mock_revoke_credentials: MagicMock, mock_authenticate: MagicMock
    ) -> None:
        """Verify that v1 passwords are NOT revoked when the grace period has not yet expired."""
        mock_authenticate.return_value = True
        mock_revoke_credentials.return_value = True
        assert isinstance(self.app.authn, IdPAuthn)

        # Set up user with both v1 and v2 passwords, v2 created recently (within grace period)
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None

        # Add a v2 credential created just 10 days ago (well within 180-day grace period)
        v2_password = Password(
            credential_id=str(ObjectId()),
            salt="$NDNv1H1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$32$32$",
            is_generated=False,
            created_by="idp",
            version=2,
            created_ts=datetime.datetime.now(tz=datetime.UTC) - timedelta(days=10),
        )
        user.credentials.add(v2_password)
        self.app.userdb.save(user)

        # Authenticate with v2
        assert self.test_user.mail_addresses.primary
        with self.app.app_context():
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        assert pwauth is not None

        # Credentials should NOT have changed (still within grace period)
        assert pwauth.credentials_changed is False, "credentials_changed should be False within grace period"

        # v1 credential should still exist
        remaining_v1 = [p for p in pwauth.user.credentials.filter(Password) if p.version == 1]
        assert len(remaining_v1) == 1, f"Expected 1 v1 credential (not revoked yet), got {len(remaining_v1)}"

        # revoke_credentials should NOT have been called
        mock_revoke_credentials.assert_not_called()
