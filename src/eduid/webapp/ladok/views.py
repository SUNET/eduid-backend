# -*- coding: utf-8 -*-
from typing import Dict, List

from flask import Blueprint

from eduid.userdb import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
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
    ladok_info = current_app.ladok_client.student_info(university_abbr=university_abbr, nin=user.nins.primary.number)
    if ladok_info is None:
        return error_response(message=LadokMsg.no_ladok_data)

    # TODO: Save ladok data for user

    return success_response(message=LadokMsg.user_linked)


@ladok_views.route('/unlink-user', methods=['POST'])
@MarshalWith(EmptyResponse)
@require_user
def unlink_user(user: User):
    # TODO: remove ladok data from user
    return success_response(message=LadokMsg.user_unlinked)
