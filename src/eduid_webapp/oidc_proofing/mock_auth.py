# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
from eduid_common.api.exceptions import ApiException

__author__ = 'lundberg'


# TODO: Not for production use
def authenticate(data):
    """
    :param data: POST data
    :type data: dict
    :return: eppn
    :rtype: str | unicode
    """
    eppn = data.get('eppn')
    current_app.logger.info('Trying to authenticate user {!s}'.format(eppn))

    if not eppn:
        msg = 'No eppn provided. No user to authenticate.'
        current_app.logger.error(msg)
        raise ApiException(status_code=401, payload={'reason': msg})

    return eppn

