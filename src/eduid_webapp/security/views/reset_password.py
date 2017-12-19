# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from flask import Blueprint, session
from flask import current_app
from u2flib_server.u2f import begin_registration, begin_authentication, complete_registration, complete_authentication

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

from eduid_userdb.credentials import U2F
from eduid_userdb.security import SecurityUser
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_and_sync_user
from eduid_common.api.schemas.u2f import U2FEnrollResponseSchema, U2FSignResponseSchema, U2FBindRequestSchema
from eduid_webapp.security.schemas import EnrollU2FTokenResponseSchema, BindU2FRequestSchema
from eduid_webapp.security.schemas import SignWithU2FTokenResponseSchema, VerifyWithU2FTokenRequestSchema
from eduid_webapp.security.schemas import VerifyWithU2FTokenResponseSchema, ModifyU2FTokenRequestSchema
from eduid_webapp.security.schemas import RemoveU2FTokenRequestSchema, SecurityResponseSchema
from eduid_webapp.security.helpers import credentials_to_registered_keys, compile_credential_list

from flask import render_template, request

__author__ = 'lundberg'


reset_password_views = Blueprint('reset_password', __name__, url_prefix='/reset-password', template_folder='templates')


@reset_password_views.route('/test', methods=['GET', 'POST'])
def reset_password():
    return 'Ok', 200
