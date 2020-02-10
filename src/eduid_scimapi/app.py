import sys
from os import environ
from typing import Any, Dict

import falcon
import yaml

from eduid_scimapi import exceptions
from eduid_scimapi.context import Context
from eduid_scimapi.middleware import HandleSCIM
from eduid_scimapi.resources.users import UsersResource

# Read config
config_path = environ.get('EDUID_AMPLUS_CONFIG')
config: Dict[str, Any] = dict()
if config_path:
    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)

context = Context(config)
context.logger.info('Starting app')

api = falcon.API(middleware=[HandleSCIM(context)])
api.req_options.media_handlers['application/scim+json'] = api.req_options.media_handlers['application/json']

# Error handlers tried in reversed declaration order
api.add_error_handler(Exception, exceptions.unexpected_error_handler)
api.add_error_handler(falcon.HTTPMethodNotAllowed, exceptions.method_not_allowed_handler)
api.add_error_handler(falcon.HTTPUnsupportedMediaType, exceptions.unsupported_media_type_handler)
api.add_error_handler(exceptions.HTTPErrorDetail)

api.add_route('/Users/', UsersResource(context=context))  # for POST
api.add_route('/Users/{user_id}', UsersResource(context=context))  # for GET

context.logger.info('app running...')
