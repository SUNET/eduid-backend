from collections.abc import Mapping
from typing import Any, cast
from unittest.mock import MagicMock

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.element import ElementKey
from eduid.userdb.idp import IdPUser
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.mfa_action import need_security_key
from eduid.webapp.idp.tests.test_api import IdPAPITests


class TestNeedSecurityKey(IdPAPITests):
    """Tests for the need_security_key function"""

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return super().update_config(config)

    def _get_idp_user(self) -> IdPUser:
        """Get the test user as an IdPUser from the IdP userdb"""
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None
        return user

    def _make_authn_data(self, cred_key: ElementKey) -> AuthnData:
        """Create an AuthnData instance for a credential"""
        return AuthnData(cred_id=cred_key, timestamp=utc_now())

    def _make_ticket(self, credentials_used: Mapping[ElementKey, AuthnData] | None = None) -> LoginContext:
        """Create a mock LoginContext ticket with the specified credentials_used"""
        if credentials_used is None:
            credentials_used = {}
        ticket = MagicMock(spec=LoginContext)
        ticket.pending_request = MagicMock()
        ticket.pending_request.credentials_used = credentials_used
        return cast(LoginContext, ticket)

    def test_user_without_fido_credentials(self) -> None:
        """User without FIDO credentials doesn't need security key"""
        user = self._get_idp_user()
        ticket = self._make_ticket()

        # Verify user has no FIDO credentials
        assert len(user.credentials.filter(FidoCredential)) == 0

        assert need_security_key(user, ticket) is False

    def test_user_with_fido_but_preference_disabled(self) -> None:
        """User with FIDO but always_use_security_key=False doesn't require MFA"""
        self.add_test_user_security_key(always_use_security_key=False)
        user = self._get_idp_user()
        ticket = self._make_ticket()

        assert need_security_key(user, ticket) is False

    def test_user_with_fido_preference_enabled_no_mfa_used(self) -> None:
        """User with FIDO and preference enabled requires security key when no MFA used"""
        self.add_test_user_security_key(always_use_security_key=True)
        user = self._get_idp_user()
        ticket = self._make_ticket(credentials_used={})

        assert need_security_key(user, ticket) is True

    def test_user_already_used_fido_credential(self) -> None:
        """User who already used FIDO doesn't need to use it again"""
        self.add_test_user_security_key(always_use_security_key=True)
        user = self._get_idp_user()

        fido_cred = user.credentials.filter(FidoCredential)[0]
        credentials_used = {fido_cred.key: self._make_authn_data(fido_cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_sweden_connect_loa3(self) -> None:
        """User who used SwedenConnect at loa3 doesn't need security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.SWECONN, trust_level="loa3")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_sweden_connect_lower_level(self) -> None:
        """User who used SwedenConnect at lower level still needs security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.SWECONN, trust_level="loa2")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is True

    def test_user_used_eidas_nf_high(self) -> None:
        """User who used eIDAS at nf-high doesn't need security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.EIDAS, trust_level="eidas-nf-high")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_eidas_nf_sub(self) -> None:
        """User who used eIDAS at nf-sub doesn't need security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.EIDAS, trust_level="eidas-nf-sub")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_eidas_lower_level(self) -> None:
        """User who used eIDAS at lower level still needs security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.EIDAS, trust_level="eidas-nf-low")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is True

    def test_user_used_bankid_uncertified_loa3(self) -> None:
        """User who used BankID at uncertified-loa3 doesn't need security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(
            trust_framework=TrustFramework.BANKID, trust_level="uncertified-loa3"
        )
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_bankid_lower_level(self) -> None:
        """User who used BankID at lower level still needs security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(
            trust_framework=TrustFramework.BANKID, trust_level="uncertified-loa2"
        )
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is True

    def test_user_used_freja_loa3(self) -> None:
        """User who used Freja at freja-loa3 doesn't need security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.FREJA, trust_level="freja-loa3")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_freja_loa3_nr(self) -> None:
        """User who used Freja at freja-loa3_nr doesn't need security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.FREJA, trust_level="freja-loa3_nr")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is False

    def test_user_used_freja_lower_level(self) -> None:
        """User who used Freja at lower level still needs security key"""
        self.add_test_user_security_key(always_use_security_key=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.FREJA, trust_level="freja-loa2")
        user = self._get_idp_user()

        credentials_used = {cred.key: self._make_authn_data(cred.key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        assert need_security_key(user, ticket) is True

    def test_user_with_fido_preference_none_requires_mfa(self) -> None:
        """User with FIDO and always_use_security_key=None (default) DOES require MFA.

        The check uses `is False`, so None is not treated as False - this means users
        who haven't explicitly opted out will still need to use their security key.
        """
        # Add security key but then set preference to None (simulating default state)
        self.add_test_user_security_key(always_use_security_key=True)
        user = self._get_idp_user()
        # Use type: ignore since we're intentionally testing behavior with None
        user.preferences.always_use_security_key = None  # type: ignore[assignment]
        # Note: we don't sync this change since we're testing the in-memory behavior
        ticket = self._make_ticket(credentials_used={})

        assert need_security_key(user, ticket) is True

    def test_credential_not_found_on_user(self) -> None:
        """Credential key in credentials_used but not found on user - should still require MFA"""
        self.add_test_user_security_key(always_use_security_key=True)
        user = self._get_idp_user()

        # Use a key that doesn't exist on the user
        fake_key = ElementKey("nonexistent_credential_key")
        credentials_used = {fake_key: self._make_authn_data(fake_key)}
        ticket = self._make_ticket(credentials_used=credentials_used)

        # Since the credential is not found, it won't match any case, so MFA is still required
        assert need_security_key(user, ticket) is True
