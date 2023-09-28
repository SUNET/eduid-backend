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
#     3. Neither the name of the NORDUnet nor the names of its
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
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from pathlib import PurePath
from typing import Any, Mapping, Optional

from bson import ObjectId
from saml2.client import Saml2Client
from werkzeug.test import TestResponse

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import ToUEvent
from eduid.userdb.user import User
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.common.session.namespaces import AuthnRequestRef, PySAML2Dicts
from eduid.webapp.idp.app import IdPApp, init_idp_app
from eduid.webapp.idp.settings.common import IdPConfig

__author__ = "ft"


class LoginState(Enum):
    S0_REDIRECT = "redirect"
    S1_LOGIN_FORM = "login-form"
    S2_VERIFY = "verify"
    S3_REDIRECT_LOGGED_IN = "redirect-logged-in"
    S4_REDIRECT_TO_ACS = "redirect-to-acs"
    S5_LOGGED_IN = "logged-in"


@dataclass
class LoginResult:
    url: str
    reached_state: LoginState
    response: TestResponse
    sso_cookie_val: Optional[str] = None


class IdPTests(EduidAPITestCase[IdPApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, *args: Any, **kwargs: Any) -> None:
        super().setUp(*args, **kwargs)
        self.idp_entity_id = "https://unittest-idp.example.edu/idp.xml"
        self.relay_state = AuthnRequestRef("test-fest")
        self.sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        # pysaml2 likes to keep state about ongoing logins, data from login to when you logout etc.
        self._pysaml2_caches = PySAML2Dicts({})
        self.pysaml2_state = StateCache(self._pysaml2_caches)  # _saml2_state in _pysaml2_caches
        self.pysaml2_identity = IdentityCache(self._pysaml2_caches)  # _saml2_identities in _pysaml2_caches
        self.pysaml2_oq = OutstandingQueriesCache(self._pysaml2_caches)  # _saml2_outstanding_queries in _pysaml2_caches
        self.saml2_client = Saml2Client(config=self.sp_config, identity_cache=self.pysaml2_identity)

    def load_app(self, config: Optional[Mapping[str, Any]]) -> IdPApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_idp_app(test_config=config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config = super().update_config(config)
        fn = PurePath(__file__).with_name("data") / "test_SSO_conf.py"
        config.update(
            {
                "pysaml2_config": str(fn),
                "fticks_secret_key": "test test",
                "eduperson_targeted_id_secret_key": "eptid_secret",
                "pairwise_id_secret_key": "pairwise_secret",
                "sso_cookie": {"key": "test_sso_cookie"},
                "eduid_site_url": "https://eduid.docker_dev",
                "tou_version": "2014-v1",  # this version is implicitly accepted on all users
                "u2f_app_id": "https://example.com",
                "u2f_valid_facets": ["https://dashboard.dev.eduid.se", "https://idp.dev.eduid.se"],
                "fido2_rp_id": "idp.example.com",
                "default_eppn_scope": "test.scope",
                "other_device_secret_key": "lx0sg0g21QUkiu9JAPfhx4hJ5prJtbk1PPE-OBvpiAk=",
                "known_devices_secret_key": "WwemHQgPm1hpx41NYaVBQpRV7BAq0OMtfF3k4H72J7c=",
                "geo_statistics_secret_key": "gk5cBWIZ6k-mNHWnA33ZpsgXfgH50Wi_s3mUNI9GF0o=",
            }
        )
        return config

    def add_test_user_tou(self, user: User, version: Optional[str] = None) -> ToUEvent:
        """Utility function to add a valid ToU to the default test user"""
        if version is None:
            version = self.app.conf.tou_version
        tou = ToUEvent(
            version=version,
            created_by="idp_tests",
            created_ts=utc_now(),
            modified_ts=utc_now(),
            event_id=str(ObjectId()),
        )
        user.tou.add(tou)
        self.amdb.save(user)
        return tou


class BasicIdPTests(IdPTests):
    def test_app_starts(self):
        assert self.app.conf.app_name == "idp"

    def test_sso_session_lifetime_config(self):
        config = dict(self.settings)

        config["sso_session_lifetime"] = 10  # expected to be interpreted as 10 minutes
        conf1 = IdPConfig(**config)
        assert conf1.sso_session_lifetime == timedelta(minutes=10)

        config["sso_session_lifetime"] = "PT5S"
        conf2 = IdPConfig(**config)
        assert conf2.sso_session_lifetime == timedelta(seconds=5)

        config["sso_session_lifetime"] = "P365D"
        conf3 = IdPConfig(**config)
        assert conf3.sso_session_lifetime == timedelta(days=365)
