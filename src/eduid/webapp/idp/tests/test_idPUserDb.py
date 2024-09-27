#!/usr/bin/python


import datetime
import logging
from unittest.mock import MagicMock, patch

from bson import ObjectId

import eduid.userdb
import eduid.webapp.common.authn
from eduid.userdb.credentials.password import Password
from eduid.userdb.mail import MailAddress
from eduid.vccs.client import VCCSClient, VCCSPasswordFactor
from eduid.webapp.common.api import exceptions
from eduid.webapp.idp.idp_authn import IdPAuthn
from eduid.webapp.idp.tests.test_api import IdPAPITests

logger = logging.getLogger(__name__)

eduid.webapp.common.authn.TESTING = True


class TestIdPUserDb(IdPAPITests):
    def test_lookup_user_by_email(self):
        _this = self.app.userdb.lookup_user(self.test_user.mail_addresses.primary.email)
        assert _this.eppn == self.test_user.eppn

    def test_lookup_user_by_eppn(self):
        _this = self.app.userdb.lookup_user(self.test_user.eppn)
        assert _this.eppn == self.test_user.eppn

    def test_password_authn(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate"):
            VCCSClient.authenticate.return_value = True
            assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
            pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
            assert pwauth.user.eppn == self.test_user.eppn
            assert pwauth.authndata is not None

    def test_verify_username_and_incorrect_password(self):
        pwauth = self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        assert pwauth is None


class TestAuthentication(IdPAPITests):
    def test_authn_unknown_user(self):
        assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
        pwauth = self.app.authn.password_authn("foo", "bar")
        assert pwauth is None

    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_authn_known_user_wrong_password(self, mock_add_credentials: MagicMock):
        mock_add_credentials.return_value = False
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
    def test_authn_known_user_right_password(self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock):
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
        assert pwauth.authndata is not None
        assert pwauth.authndata.cred_id == factor.credential_id

    @patch("eduid.vccs.client.VCCSClient.authenticate")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def test_authn_expired_credential(self, mock_add_credentials: MagicMock, mock_authenticate: MagicMock):
        mock_add_credentials.return_value = False
        mock_authenticate.return_value = True
        assert isinstance(self.test_user, eduid.userdb.User)
        assert isinstance(self.app.authn, IdPAuthn)  # help pycharm
        passwords = self.test_user.credentials.to_list()
        assert isinstance(passwords[0], Password)
        factor = VCCSPasswordFactor("foo", str(passwords[0].key), salt=passwords[0].salt)
        self.app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        # Store a successful authentication using this credential three year ago
        three_years_ago = datetime.datetime.now() - datetime.timedelta(days=3 * 365)
        self.app.authn.authn_store.credential_success([passwords[0].key], three_years_ago)
        with self.assertRaises(exceptions.EduidForbidden):
            assert isinstance(self.test_user.mail_addresses.primary, MailAddress)
            self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
        # Do the same thing again to make sure we didn't accidentally update the
        # 'last successful login' timestamp when it was a successful login with an
        # expired credential.
        with self.assertRaises(exceptions.EduidForbidden):
            assert isinstance(self.test_user.mail_addresses.primary, MailAddress)
            self.app.authn.password_authn(self.test_user.mail_addresses.primary.email, "foo")
