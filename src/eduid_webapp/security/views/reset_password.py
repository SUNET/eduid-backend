# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from flask import Blueprint, session, request
from flask import current_app

from eduid_userdb.security import SecurityUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user

from flask import render_template, request

__author__ = 'lundberg'


reset_password_views = Blueprint('reset_password', __name__, url_prefix='/reset-password', template_folder='templates')


@reset_password_views.route('/', methods=['GET'])
def reset_password():
    current_app.logger.debug('Starting password reset')
    return render_template('reset_password.html')
