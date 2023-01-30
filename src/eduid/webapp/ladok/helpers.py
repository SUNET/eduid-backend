from enum import unique
from uuid import UUID

from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.ladok import Ladok, University, UniversityName
from eduid.userdb.logs.element import LadokProofing
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.messages import CommonMsg, FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.ladok.app import current_ladok_app as current_app

__author__ = "lundberg"


@unique
class LadokMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    no_verified_nin = "ladok.no-verified-nin"
    no_ladok_data = "ladok.no-data-for-user"
    missing_university = "ladok.missing-university"
    user_linked = "ladok.user-linked-successfully"
    user_unlinked = "ladok.user-unlinked-successfully"


def link_user_BACKDOOR(user: User, ladok_name: str) -> FluxData:
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    university = current_app.ladok_client.universities.get(ladok_name)
    if not university:
        return error_response(message=LadokMsg.missing_university)

    if ladok_name not in current_app.conf.dev_fake_users_in:
        current_app.logger.info(f"BACKDOOR: University {ladok_name} does not allow linking (not in dev_fake_users_in)")
        return error_response(message=LadokMsg.no_ladok_data)

    ladok_data = Ladok(
        external_id=UUID("00000000-1111-2222-3333-444444444444"),
        university=University(ladok_name=ladok_name, name=UniversityName(sv=university.name.sv, en=university.name.en)),
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
        proofing_method="eduid_ladok_dev",
        proofing_version="2021v1",
        created_by="eduid-ladok",
    )

    # Save proofing log entry and save user
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info("BACKDOOR: Recorded Ladok linking in the proofing log")
        try:
            save_and_sync_user(proofing_user)
        except AmTaskFailed as e:
            current_app.logger.error("BACKDOOR: Linking to Ladok failed")
            current_app.logger.error(f"BACKDOOR: {e}")
            return error_response(message=CommonMsg.temp_problem)
        current_app.stats.count(name="ladok_linked")

    current_app.logger.info("BACKDOOR: Ladok linked successfully")
    current_app.logger.debug(f"Ladok data in response: {ladok_data}")
    return success_response(payload={"ladok": ladok_data})
