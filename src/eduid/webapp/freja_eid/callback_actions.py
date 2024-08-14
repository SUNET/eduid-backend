from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.freja_eid.app import current_freja_eid_app as current_app
from eduid.webapp.freja_eid.callback_enums import FrejaEIDAction
from eduid.webapp.freja_eid.helpers import FrejaEIDMsg, FrejaEIDTokenResponse
from eduid.webapp.freja_eid.proofing import get_proofing_functions

__author__ = "lundberg"


@acs_action(FrejaEIDAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a Freja OIDC userinfo to verify a users' identity.
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(message=FrejaEIDMsg.method_not_available)

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert isinstance(parsed.info, FrejaEIDTokenResponse)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=current_app.conf.app_name, config=current_app.conf, backdoor=args.backdoor
    )

    current = proofing.get_identity(user)
    if current and current.is_verified:
        current_app.logger.error(f"User already has a verified identity for {args.proofing_method.method}")
        current_app.logger.debug(f"Current: {current}. Assertion: {args.session_info}")
        return ACSResult(message=ProofingMsg.identity_already_verified)

    verify_result = proofing.verify_identity(user=user)
    if verify_result.error is not None:
        return ACSResult(message=verify_result.error)

    return ACSResult(success=True, message=FrejaEIDMsg.identity_verify_success)
