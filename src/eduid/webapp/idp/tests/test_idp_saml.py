"""Unit tests for IdP_SAMLRequest.get_signup_authn_requirements().

These test the helper in isolation, without going through a full SAML request/response
round-trip: what matters here is the MFA-context-set/entity-category-to-AL/comparison logic,
not pysaml2 parsing (which is already exercised via the full login flow in test_login.py).
"""

from collections.abc import Mapping
from types import SimpleNamespace
from typing import cast

from eduid.webapp.common.session.namespaces import IdPAuthnRequirements
from eduid.webapp.idp.idp_saml import IdP_SAMLRequest


class _FakeSamlReq:
    """Exposes just what get_signup_authn_requirements() reads from an IdP_SAMLRequest."""

    def __init__(
        self,
        requested_contexts: list[str] | None = None,
        comparison: str | None = None,
        entity_categories: object = None,
        raise_on_contexts: bool = False,
        raise_on_attributes: bool = False,
    ) -> None:
        self.requested_contexts = requested_contexts or []
        self.comparison = comparison
        self.entity_categories = entity_categories
        self.raise_on_contexts = raise_on_contexts
        self.raise_on_attributes = raise_on_attributes

    def get_requested_authn_contexts(self) -> list[str]:
        if self.raise_on_contexts:
            raise RuntimeError("boom")
        return self.requested_contexts

    @property
    def raw_requested_authn_context(self) -> SimpleNamespace | None:
        if self.raise_on_contexts:
            raise RuntimeError("boom")
        if self.comparison is None:
            return None
        return SimpleNamespace(comparison=self.comparison)

    @property
    def sp_entity_attributes(self) -> Mapping[str, object]:
        if self.raise_on_attributes:
            raise RuntimeError("metadata boom")
        attrs: dict[str, object] = {}
        if self.entity_categories is not None:
            attrs["http://macedir.org/entity-category"] = self.entity_categories
        return attrs


def _get_requirements(fake: _FakeSamlReq) -> IdPAuthnRequirements:
    return IdP_SAMLRequest.get_signup_authn_requirements(cast(IdP_SAMLRequest, fake))


class TestGetSignupAuthnRequirements:
    def test_no_requirements(self) -> None:
        """SFA-only request: no MFA, no AL requirement."""
        req = _get_requirements(_FakeSamlReq())
        assert req.requested_authn_contexts == []
        assert req.comparison is None
        assert req.require_mfa is False
        assert req.minimum_assurance_level is None

    def test_refeds_mfa(self) -> None:
        req = _get_requirements(_FakeSamlReq(requested_contexts=["https://refeds.org/profile/mfa"], comparison="exact"))
        assert req.require_mfa is True
        assert req.minimum_assurance_level is None
        assert req.comparison == "exact"

    def test_eduid_mfa(self) -> None:
        req = _get_requirements(_FakeSamlReq(requested_contexts=["https://eduid.se/specs/mfa"]))
        assert req.require_mfa is True

    def test_fido_u2f_is_not_mfa(self) -> None:
        """FIDO_U2F is deliberately not treated as an MFA signal (matches assurance.py)."""
        req = _get_requirements(
            _FakeSamlReq(requested_contexts=["https://www.swamid.se/specs/id-fido-u2f-ce-transports"])
        )
        assert req.require_mfa is False

    def test_digg_loa2_implies_mfa_and_al3_floor(self) -> None:
        req = _get_requirements(
            _FakeSamlReq(
                requested_contexts=["http://id.elegnamnden.se/loa/1.0/loa2"],
                comparison="minimum",
            )
        )
        assert req.require_mfa is True
        assert req.minimum_assurance_level == "al3"
        assert req.comparison == "minimum"

    def test_entity_category_al2(self) -> None:
        req = _get_requirements(_FakeSamlReq(entity_categories=["http://www.swamid.se/policy/assurance/al2"]))
        assert req.minimum_assurance_level == "al2"
        assert req.require_mfa is False

    def test_entity_category_al3_implies_mfa(self) -> None:
        """SWAMID policy: AL3 implies MFA even if the AuthnRequest didn't ask for it."""
        req = _get_requirements(_FakeSamlReq(entity_categories=["http://www.swamid.se/policy/assurance/al3"]))
        assert req.minimum_assurance_level == "al3"
        assert req.require_mfa is True

    def test_multiple_entity_categories_highest_wins(self) -> None:
        req = _get_requirements(
            _FakeSamlReq(
                entity_categories=[
                    "http://www.swamid.se/policy/assurance/al2",
                    "http://www.swamid.se/policy/assurance/al3",
                ]
            )
        )
        assert req.minimum_assurance_level == "al3"

    def test_multiple_entity_categories_order_independent(self) -> None:
        """Highest wins regardless of list order (never string sorting)."""
        req = _get_requirements(
            _FakeSamlReq(
                entity_categories=[
                    "http://www.swamid.se/policy/assurance/al3",
                    "http://www.swamid.se/policy/assurance/al2",
                ]
            )
        )
        assert req.minimum_assurance_level == "al3"

    def test_unknown_requested_context_fails_soft(self) -> None:
        """An authn context class ref not in the known MFA set is simply not a requirement."""
        req = _get_requirements(_FakeSamlReq(requested_contexts=["urn:some:unknown:context"]))
        assert req.require_mfa is False
        assert req.minimum_assurance_level is None
        assert req.requested_authn_contexts == ["urn:some:unknown:context"]

    def test_unrecognised_entity_category_fails_soft(self) -> None:
        """An entity category we don't recognise (e.g. some other AL scheme) is just ignored."""
        req = _get_requirements(_FakeSamlReq(entity_categories=["https://refeds.org/category/code-of-conduct/v2"]))
        assert req.minimum_assurance_level is None

    def test_no_entity_categories_at_all(self) -> None:
        """No entity-category attribute present at all -> AL1 baseline (None), not an error."""
        req = _get_requirements(_FakeSamlReq())
        assert req.minimum_assurance_level is None

    def test_malformed_entity_categories_fails_soft(self) -> None:
        """A non-list value for the entity-category attribute must never raise - just be ignored."""
        req = _get_requirements(
            _FakeSamlReq(
                requested_contexts=["https://refeds.org/profile/mfa"],
                entity_categories="http://www.swamid.se/policy/assurance/al2",  # a bare string, not a list
            )
        )
        assert req.minimum_assurance_level is None
        # Unaffected parts of the requirements are still derived correctly
        assert req.require_mfa is True

    def test_sp_entity_attributes_raises_fails_soft(self) -> None:
        """If reading the SP's entity attributes blows up entirely, still return sane defaults."""
        req = _get_requirements(
            _FakeSamlReq(requested_contexts=["https://refeds.org/profile/mfa"], raise_on_attributes=True)
        )
        assert req.minimum_assurance_level is None
        assert req.require_mfa is True

    def test_requested_authn_context_raises_fails_soft(self) -> None:
        """If parsing the requested authn context blows up entirely, still return sane defaults."""
        req = _get_requirements(_FakeSamlReq(raise_on_contexts=True))
        assert req.requested_authn_contexts == []
        assert req.require_mfa is False
        assert req.comparison is None
