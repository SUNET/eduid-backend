# -*- coding: utf-8 -*-
from flask import Blueprint
from typing import Dict, List

from eduid.userdb import User
from eduid.userdb.ladok import Ladok, University
from eduid.userdb.logs.element import LadokProofing
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.exceptions import AmTaskFailed
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.ladok.app import current_ladok_app as current_app

__author__ = 'lundberg'

from eduid.webapp.ladok.helpers import LadokMsg
from eduid.webapp.ladok.schemas import LinkUserRequest, UniversityInfoResponseSchema

ladok_views = Blueprint('ladok', __name__, url_prefix='')


@ladok_views.route('/', methods=['GET'])
@MarshalWith(EmptyResponse)
@require_user
def get_csrf(user: User) -> FluxData:
    return success_response(payload=None, message=None)


@ladok_views.route('/universities', methods=['GET'])
@MarshalWith(UniversityInfoResponseSchema)
@require_user
def get_university_info(user: User):
    res: List[Dict[str, str]] = []
    for abbr, names in current_app.ladok_client.universities.names.items():
        uni = names.dict()
        uni['abbr'] = abbr
        res.append(uni)
    return success_response(payload={'universities': res})


@ladok_views.route('/link-user', methods=['POST'])
@MarshalWith(EmptyResponse)
@UnmarshalWith(LinkUserRequest)
@require_user
def link_user(user: User, university_abbr: str):
    if not user.nins.verified:
        current_app.logger.error('User has no verified nin')
        return error_response(message=LadokMsg.no_verified_nin)

    assert user.nins.primary is not None  # please mypy
    ladok_info = current_app.ladok_client.get_user_info(university_abbr=university_abbr, nin=user.nins.primary.number)
    if ladok_info is None:
        return error_response(message=LadokMsg.no_ladok_data)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    university = current_app.ladok_client.universities.names[university_abbr]
    ladok_data = Ladok(
        external_id=ladok_info.external_id,
        university=University(abbr=university_abbr, name_sv=university.name_sv, name_en=university.name_en),
    )
    proofing_user.ladok = ladok_data
    assert proofing_user.nins.primary is not None  # please mypy
    proofing_log_entry = LadokProofing(
        eppn=proofing_user.eppn,
        nin=proofing_user.nins.primary.number,
        external_id=str(ladok_data.external_id),
        proofing_version='2021v1',
        created_by='eduid-ladok',
    )

    # Save proofing log entry and save user
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info('Recorded Ladok linking in the proofing log')
        try:
            save_and_sync_user(proofing_user)
        except AmTaskFailed as e:
            current_app.logger.error('Linking to Ladok failed')
            current_app.logger.error('{}'.format(e))
            return error_response(message=CommonMsg.temp_problem)
        current_app.stats.count(name='ladok_linked')

    current_app.logger.info('Ladok linked successfully')
    return success_response(message=LadokMsg.user_linked)


@ladok_views.route('/unlink-user', methods=['POST'])
@MarshalWith(EmptyResponse)
@require_user
def unlink_user(user: User):
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    proofing_user.ladok = None
    try:
        save_and_sync_user(proofing_user)
    except AmTaskFailed as e:
        current_app.logger.error('Unlinking to Ladok failed')
        current_app.logger.error('{}'.format(e))
        return error_response(message=CommonMsg.temp_problem)
    current_app.stats.count(name='ladok_unlinked')

    current_app.logger.info('Ladok unlinked successfully')
    return success_response(message=LadokMsg.user_unlinked)
