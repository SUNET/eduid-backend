from typing import Dict, Optional

import falcon

from eduid.common.config.parsers import load_config

from eduid.scimapi import exceptions
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.middleware import HandleAuthentication, HandleSCIM
from eduid.scimapi.resources.events import EventsResource
from eduid.scimapi.resources.groups import GroupSearchResource, GroupsResource
from eduid.scimapi.resources.invites import InviteSearchResource, InvitesResource
from eduid.scimapi.resources.login import LoginResource
from eduid.scimapi.resources.status import HealthCheckResource
from eduid.scimapi.resources.users import UsersResource, UsersSearchResource


def init_api(name: str = 'scimapi', test_config: Optional[Dict] = None) -> falcon.API:
    config = load_config(typ=ScimApiConfig, app_name=name, ns='api', test_config=test_config)
    context = Context(config=config)
    context.logger.info(f'Starting {name} app')

    api = falcon.API(middleware=[HandleSCIM(context), HandleAuthentication(context)])
    api.req_options.media_handlers['application/scim+json'] = api.req_options.media_handlers['application/json']

    # Error handlers tried in reversed declaration order
    api.add_error_handler(Exception, exceptions.unexpected_error_handler)
    api.add_error_handler(falcon.HTTPMethodNotAllowed, exceptions.method_not_allowed_handler)
    api.add_error_handler(falcon.HTTPUnsupportedMediaType, exceptions.unsupported_media_type_handler)
    api.add_error_handler(exceptions.HTTPErrorDetail)

    # Login
    # TODO: Move bearer token generation to a separate API
    api.add_route('/login/', LoginResource(context=context))

    # Users
    api.add_route('/Users/', UsersResource(context=context))  # for POST
    api.add_route('/Users/{scim_id}', UsersResource(context=context))  # for GET/PUT
    api.add_route('/Users/.search', UsersSearchResource(context=context))  # for POST

    # Groups
    api.add_route('/Groups/', GroupsResource(context=context))
    api.add_route('/Groups/{scim_id}', GroupsResource(context=context))
    api.add_route('/Groups/.search', GroupSearchResource(context=context))

    # Invites
    api.add_route('/Invites/', InvitesResource(context=context))
    api.add_route('/Invites/{scim_id}', InvitesResource(context=context))
    api.add_route('/Invites/.search', InviteSearchResource(context=context))

    # Events
    api.add_route('/Events/', EventsResource(context=context))
    api.add_route('/Events/{scim_id}', EventsResource(context=context))

    # Status
    api.add_route('/status/healthy', HealthCheckResource(context=context))

    context.logger.info('app running...')
    return api
