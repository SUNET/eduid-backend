# -*- coding: utf-8 -*-

from flask import Blueprint

from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_webapp.{{cookiecutter.directory_name}}.app import current_{{cookiecutter.directory_name}}_app as current_app

__author__ = '{{cookiecutter.author}}'

{{cookiecutter.directory_name}}_views = Blueprint('{{cookiecutter.directory_name}}', __name__, url_prefix='', template_folder='templates')


@{{cookiecutter.directory_name}}_views.route('/index', methods=['GET'])
@UnmarshalWith()
@MarshalWith()
@require_user
def index(user):
    pass
