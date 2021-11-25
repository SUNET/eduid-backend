# -*- coding: utf-8 -*-
from flask import Blueprint

from eduid.webapp.common.api.decorators import MarshalWith, require_user
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse

__author__ = 'lundberg'


ladok_views = Blueprint('ladok', __name__, url_prefix='')


@ladok_views.route('/', methods=['GET'])
@MarshalWith(EmptyResponse)
@require_user
def index(user) -> FluxData:
    return success_response(payload=None, message=None)
