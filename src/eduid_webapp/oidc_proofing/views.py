# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import request, session, redirect, abort
from flask import current_app, Blueprint

__author__ = 'lundberg'

oidc_proofing_views = Blueprint('oidc_proofing', __name__, url_prefix='')


@oidc_proofing_views.route('/')
def hello_world():
    return 'Hello'