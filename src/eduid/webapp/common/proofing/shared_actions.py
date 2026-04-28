"""
Shared action helpers for external identity proofing ACS/callback handlers.

Each webapp's action function becomes a thin wrapper that delegates to these helpers,
passing in app-specific callables and message constants.
"""

from __future__ import annotations

import logging

from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.proofing.methods import ProofingMethodSAML
from eduid.webapp.common.proofing.saml_helpers import is_required_loa, is_valid_authn_instant

logger = logging.getLogger(__name__)


def run_common_saml_checks(
    args: ACSArgs,
    *,
    authn_context_mismatch_msg: TranslatableMsg,
    authn_instant_too_old_msg: TranslatableMsg,
    loa_authn_context_map: dict[str, str],
) -> ACSResult | None:
    """Shared SAML validation: LoA check and authn instant freshness.

    :param args: ACS action arguments
    :param authn_context_mismatch_msg: App-specific error message for LoA mismatch
    :param authn_instant_too_old_msg: App-specific error message for stale authn
    :param loa_authn_context_map: Config mapping LoA names to authn context URIs
    :returns: ACSResult with error if validation fails, None on success
    """
    assert isinstance(args.proofing_method, ProofingMethodSAML)  # please mypy
    if not is_required_loa(args.session_info, args.proofing_method.required_loa, loa_authn_context_map):
        logger.error("SAML response did not meet required LOA")
        args.authn_req.error = True
        args.authn_req.status = authn_context_mismatch_msg.value
        return ACSResult(message=authn_context_mismatch_msg)

    if not is_valid_authn_instant(args.session_info):
        logger.error("SAML response was not a valid reauthn")
        args.authn_req.error = True
        args.authn_req.status = authn_instant_too_old_msg.value
        return ACSResult(message=authn_instant_too_old_msg)

    return None
