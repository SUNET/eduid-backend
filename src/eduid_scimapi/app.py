from typing import Optional, Dict

import falcon

from eduid_scimapi import exceptions
from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.context import Context
from eduid_scimapi.middleware import HandleSCIM
from eduid_scimapi.resources.users import UsersResource, UsersSearchResource


def init_api(name: str, test_config: Optional[Dict] = None, debug: bool = False) -> falcon.API:
    config = ScimApiConfig.init_config(ns='api', app_name=name, test_config=test_config, debug=debug)
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
    api.add_route('/Users/{scim_id}', UsersResource(context=context))  # for GET/PUT

    api.add_route('/Users/.search', UsersSearchResource(context=context))  # for POST

    context.logger.info('app running...')
    return api
