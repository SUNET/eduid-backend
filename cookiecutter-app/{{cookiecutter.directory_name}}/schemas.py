# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFResponseMixin, CSRFRequestMixin
from eduid_common.api.schemas.validators import validate_nin

__author__ = '{{cookiecutter.author}}'


class {{cookiecutter.class_name}}RequestSchema(EduidSchema, CSRFRequestMixin):
    pass


class {{cookiecutter.class_name}}ResponseSchema(EduidSchema, CSRFResponseMixin):
    pass
