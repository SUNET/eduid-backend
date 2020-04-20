from falcon import HTTPForbidden, Request, Response
from jose import ExpiredSignatureError, jwt

from eduid_scimapi.context import Context
from eduid_scimapi.exceptions import Unauthorized, UnsupportedMediaTypeMalformed
from eduid_scimapi.resources.base import BaseResource


class HandleSCIM(object):
    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        self.context.logger.debug(f'process_request: {req.method} {req.path}')

        if req.method == 'POST':
            if req.path == '/login':
                if req.content_type != 'application/json':
                    raise UnsupportedMediaTypeMalformed(
                        detail=f'{req.content_type} is an unsupported media type for /login'
                    )
            elif req.content_type != 'application/scim+json':
                raise UnsupportedMediaTypeMalformed(detail=f'{req.content_type} is an unsupported media type')

    def process_response(self, req: Request, resp: Response, resource: BaseResource, req_succeeded: bool):
        self.context.logger.debug(f'process_response: {resource} {req.method} {req.path}')

        # Default to 'application/json' if responding with an error message
        if req_succeeded:
            # candidates should be sorted by increasing desirability
            preferred = req.client_prefers(('application/json', 'application/scim+json'))
            self.context.logger.debug(f'Client prefers content-type {preferred}')
            if preferred is None:
                preferred = 'application/scim+json'
                self.context.logger.debug(f'Default content-type {preferred} used')
            resp.content_type = preferred


class HandleAuthentication(object):
    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        if req.path == '/login':
            return

        if not req.auth or not req.auth.startswith('Bearer '):
            # TODO: Authorization is optional at the moment
            self.context.logger.info('No authorization header provided - proceeding anyway')
            req.context['data_owner'] = 'eduid.se'
            req.context['userdb'] = self.context.get_database(req.context['data_owner'])
            return

        token = req.auth[len('Bearer ') :]
        try:
            claims = jwt.decode(token, self.context.config.authorization_token_secret, algorithms=['HS256'])
        except ExpiredSignatureError:
            self.context.logger.info(f'Bearer token expired')
            raise Unauthorized(detail='Signature expired')

        data_owner = claims.get('data_owner')
        if not self.context.get_database(data_owner):
            self.context.logger.info(f'No database available for data_owner {repr(data_owner)}')
            raise Unauthorized(detail='Unknown data_owner')

        req.context['data_owner'] = data_owner
        req.context['userdb'] = self.context.get_database(data_owner)

        self.context.logger.debug(f'Bearer token data owner: {data_owner}')

    def process_response(self, req: Request, resp: Response, resource: BaseResource, req_succeeded: bool):
        pass
