# -*- coding: utf-8 -*-
from eduid.userdb import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.eidas.proofing import get_proofing_functions
from eduid.webapp.svipe_id.app import current_svipe_id_app as current_app
from eduid.webapp.svipe_id.callback_enums import SvipeIDAction
from eduid.webapp.svipe_id.helpers import SvipeIDMsg

__author__ = "lundberg"


@acs_action(SvipeIDAction.verify_identity)
@require_user
def verify_identity_action(user: User, args: ACSArgs) -> ACSResult:
    """
    Use a Svipe ID userinfo to verify a users' identity.
    """
    # please type checking
    if not args.proofing_method:
        return ACSResult(message=SvipeIDMsg.method_not_available)

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # please type checking
    assert parsed.info

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

    return ACSResult(success=True, message=SvipeIDMsg.identity_verify_success)
