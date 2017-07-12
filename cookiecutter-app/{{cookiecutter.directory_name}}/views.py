# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app

from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith

__author__ = '{{cookiecutter.author}}'

{{cookiecutter.directory_name}}_views = Blueprint('{{cookiecutter.directory_name}}', __name__, url_prefix='', template_folder='templates')


@{{cookiecutter.directory_name}}_views.route('/index', methods=['GET'])
@UnmarshalWith()
@MarshalWith()
@require_user
def index(user):
    pass
