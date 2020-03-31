from falcon import Request, Response

from eduid_scimapi.context import Context
from eduid_scimapi.exceptions import UnsupportedMediaTypeMalformed
from eduid_scimapi.resources.base import BaseResource


class HandleSCIM(object):
    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        self.context.logger.debug(f'process_request: {req.method} {req.path}')

        # TODO: Use bearer tokens to authenticate request and choose the appropriate database
        req.context['data_owner'] = 'eduid.se'
        req.context['userdb'] = self.context.get_database(req.context['data_owner'])

        if req.method == 'POST':
            if req.content_type != 'application/scim+json':
                raise UnsupportedMediaTypeMalformed(detail=f'{req.content_type} is an unsupported media type')

    def process_response(self, req: Request, resp: Response, resource: BaseResource, req_succeeded: bool):
        self.context.logger.debug(f'process_response: {resource} {req.method} {req.path}')

        # Default to 'application/json' if responding with an error message
        if req_succeeded:
            preferred = req.client_prefers(('application/scim+json', 'application/json'))
            self.context.logger.debug(f'Client prefers content-type {preferred}')
            if preferred is None:
                preferred = 'application/scim+json'
                self.context.logger.debug(f'Default content-type {preferred} used')
            resp.content_type = preferred
