"""
Parity between the oidceid and samleid messages.

NOTE: this test imports samleid and oidceid side by side. Webapps must not import each other, which is why it
lives here and not under either app; the cross-webapp import is test-only, like in test_app_conformance.py.
"""

from dataclasses import fields

from eduid.webapp.common.proofing.swedenconnect.flow import SwedenConnectMsgs
from eduid.webapp.oidceid.helpers import OIDCEID_MSGS, OidcEidMsg
from eduid.webapp.samleid.helpers import SamlEidMsg


def test_oidceid_msg_has_all_samleid_members() -> None:
    assert {m.name for m in SamlEidMsg} <= {m.name for m in OidcEidMsg}


def test_oidceid_msg_extra_members() -> None:
    assert {m.name for m in OidcEidMsg} - {m.name for m in SamlEidMsg} == {
        "authn_request_failed",
        "authorization_error",
    }


def test_oidceid_msg_values_are_namespaced() -> None:
    for member in OidcEidMsg:
        assert member.value == f"oidceid.{member.name}"


def test_oidceid_msgs_cover_shared_flow() -> None:
    for field in fields(SwedenConnectMsgs):
        assert getattr(OIDCEID_MSGS, field.name) is OidcEidMsg[field.name]
