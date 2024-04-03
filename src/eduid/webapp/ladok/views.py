from flask import Blueprint

from eduid.common.config.base import EduidEnvironment
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.ladok import Ladok, University, UniversityName
from eduid.userdb.logs.element import LadokProofing
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.ladok.app import current_ladok_app as current_app

__author__ = "lundberg"

from eduid.webapp.ladok.client import LadokClientException
from eduid.webapp.ladok.helpers import LadokMsg, link_user_BACKDOOR
from eduid.webapp.ladok.schemas import LinkUserRequest, LinkUserResponse, UniversityInfoResponseSchema

ladok_views = Blueprint("ladok", __name__, url_prefix="")


@ladok_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def get_csrf(user: User) -> FluxData:
    return success_response(payload=None, message=None)


@ladok_views.route("/universities", methods=["GET"])
@MarshalWith(UniversityInfoResponseSchema)
@require_user
def get_university_info(user: User) -> FluxData:
    return success_response(payload={"universities": current_app.ladok_client.universities})


@ladok_views.route("/link-user", methods=["POST"])
@UnmarshalWith(LinkUserRequest)
@MarshalWith(LinkUserResponse)
@require_user
def link_user(user: User, ladok_name: str) -> FluxData:
    if user.identities.nin is None or user.identities.nin.is_verified is False:
        current_app.logger.error("User has no verified nin")
        return error_response(message=LadokMsg.no_verified_nin)

    # Backdoor for the selenium integration tests or local dev environment
    if current_app.conf.environment is EduidEnvironment.dev or check_magic_cookie(current_app.conf):
        return link_user_BACKDOOR(user=user, ladok_name=ladok_name)

    assert user.identities.nin is not None  # please mypy
    try:
        ladok_info = current_app.ladok_client.get_user_info(ladok_name=ladok_name, nin=user.identities.nin.number)
    except LadokClientException:
        current_app.logger.error(f"{ladok_name} not found")
        return error_response(message=LadokMsg.missing_university)

    if ladok_info is None:
        return error_response(message=LadokMsg.no_ladok_data)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    university = current_app.ladok_client.universities[ladok_name]
    ladok_data = Ladok(
        external_id=ladok_info.external_id,
        university=University(
            ladok_name=university.ladok_name, name=UniversityName(sv=university.name.sv, en=university.name.en)
        ),
        is_verified=True,
        verified_by="eduid-ladok",
    )
    proofing_user.ladok = ladok_data
    assert proofing_user.identities.nin is not None  # please mypy
    proofing_log_entry = LadokProofing(
        eppn=proofing_user.eppn,
        nin=proofing_user.identities.nin.number,
        external_id=str(ladok_data.external_id),
        ladok_name=ladok_name,
        proofing_version="2021v1",
        created_by="eduid-ladok",
    )

    # Save proofing log entry and save user
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info("Recorded Ladok linking in the proofing log")
        try:
            save_and_sync_user(proofing_user)
        except AmTaskFailed as e:
            current_app.logger.error("Linking to Ladok failed")
            current_app.logger.error(f"{e}")
            return error_response(message=CommonMsg.temp_problem)
        current_app.stats.count(name="ladok_linked")

    current_app.logger.info("Ladok linked successfully")
    return success_response(payload={"ladok": ladok_data})


@ladok_views.route("/unlink-user", methods=["POST"])
@MarshalWith(EmptyResponse)
@require_user
def unlink_user(user: User) -> FluxData:
    if user.ladok is None:
        return success_response(message=LadokMsg.user_unlinked)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    proofing_user.ladok = None  # type: ignore[assignment]
    try:
        save_and_sync_user(proofing_user)
    except AmTaskFailed as e:
        current_app.logger.error("Unlinking from Ladok failed")
        current_app.logger.error(f"{e}")
        return error_response(message=CommonMsg.temp_problem)
    current_app.stats.count(name="ladok_unlinked")
    current_app.logger.info("Ladok unlinked successfully")

    return success_response(message=LadokMsg.user_unlinked)
