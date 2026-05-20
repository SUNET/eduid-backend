from pydantic import ValidationError

from eduid.userdb.logs import OrcidProofing
from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.user import User
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.orcid.app import current_orcid_app as current_app
from eduid.webapp.orcid.callback_enums import OrcidAction
from eduid.webapp.orcid.helpers import OrcidMsg, OrcidUserinfo


@acs_action(OrcidAction.connect_orcid)
@require_user
def connect_orcid_action(user: User, args: ACSArgs) -> ACSResult:
    session_info = args.session_info

    id_token = session_info["id_token"]

    try:
        userinfo = OrcidUserinfo(**session_info["userinfo"])
    except (ValidationError, KeyError) as e:
        current_app.logger.error(f"Failed to parse userinfo: {e}")
        return ACSResult(message=OrcidMsg.authz_error)

    if userinfo.sub != id_token["sub"]:
        current_app.logger.error(f"The 'sub' of userinfo does not match 'sub' of ID Token for user {user.eppn}.")
        return ACSResult(message=OrcidMsg.sub_mismatch)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    oidc_id_token = OidcIdToken(
        iss=id_token["iss"],
        sub=id_token["sub"],
        aud=id_token["aud"],
        exp=id_token["exp"],
        iat=id_token["iat"],
        nonce=id_token["nonce"],
        auth_time=id_token["auth_time"],
        created_by="orcid",
    )
    oidc_authz = OidcAuthorization(
        access_token=session_info["access_token"],
        token_type=session_info["token_type"],
        id_token=oidc_id_token,
        expires_in=session_info["expires_in"],
        refresh_token=session_info["refresh_token"],
        created_by="orcid",
    )
    orcid_element = Orcid(
        id=userinfo.orcid,
        name=userinfo.name,
        given_name=userinfo.given_name,
        family_name=userinfo.family_name,
        is_verified=True,
        oidc_authz=oidc_authz,
        created_by="orcid",
    )
    orcid_proofing = OrcidProofing(
        eppn=proofing_user.eppn,
        created_by="orcid",
        orcid=orcid_element.id,
        issuer=orcid_element.oidc_authz.id_token.iss,
        audience=orcid_element.oidc_authz.id_token.aud,
        proofing_method="oidc",
        proofing_version="2018v1",
    )

    if not current_app.proofing_log.save(orcid_proofing):
        current_app.logger.error("ORCID proofing data NOT saved, failed to save proofing log")
        return ACSResult(message=CommonMsg.temp_problem)

    current_app.logger.info("ORCID proofing data saved to log")
    proofing_user.orcid = orcid_element
    save_and_sync_user(proofing_user)
    current_app.logger.info("ORCID proofing data saved to user")

    return ACSResult(success=True, message=OrcidMsg.authz_success)
