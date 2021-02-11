# -*- coding: utf-8 -*-
import logging
import pprint

from falcon import HTTP_200, Request, Response

from eduid_scimapi.resources.base import BaseResource

__author__ = 'lundberg'

logger = logging.getLogger('eduid_scimapi.notifications')


class NotificationLoggingResource(BaseResource):
    def on_post(self, req: Request, resp: Response):
        pp = pprint.PrettyPrinter(indent=4)
        logger.info(f'Headers: {pp.pformat(req.headers)}')
        logger.info(f'Body: {pp.pformat(req.media)}')
        resp.status = HTTP_200
        resp.body = 'OK'
