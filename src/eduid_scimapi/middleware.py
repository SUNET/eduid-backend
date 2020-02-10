from falcon import Request, Response

from eduid_scimapi.context import Context
from eduid_scimapi.exceptions import UnsupportedMediaTypeMalformed


class HandleSCIM(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        self.context.logger.debug(f'process_request: {req.method} {req.path}')
        if req.method == 'POST':
            if req.content_type != 'application/scim+json':
                raise UnsupportedMediaTypeMalformed(detail=f'{req.content_type} is an unsupported media type')
