import logging
from functools import wraps

from flask import jsonify, request

from eduid.webapp.common.api.schemas.models import FluxFailResponse
from eduid.webapp.common.session import session
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.known_device import BrowserDeviceInfo
from eduid.webapp.idp.login import get_ticket
from eduid.webapp.idp.service import SAMLQueryParams
from eduid.webapp.idp.sso_session import get_sso_session

logger = logging.getLogger(__name__)


def require_ticket(f):
    @wraps(f)
    def require_ticket_decorator(*args, **kwargs):
        """Decorator to turn the 'ref' parameter sent by the frontend into a ticket (LoginContext)"""
        if 'ref' not in kwargs:
            logger.debug(f'Login ref not supplied')
            return _flux_error(IdPMsg.bad_ref)
        ref = kwargs.pop('ref')

        _info = SAMLQueryParams(request_ref=ref)
        ticket = get_ticket(_info, None)
        if not ticket:
            logger.debug(f'Login ref {ref} not found in pending_requests')
            return _flux_error(IdPMsg.bad_ref)

        logger.debug(f'Found ticket {ticket}')

        this_device = kwargs.get('this_device')
        if this_device:
            kwargs.pop('this_device')
            remember_me = None
            if 'remember_me' in kwargs:
                # schema should have decoded this into a proper boolean already, this is just for the type checking
                remember_me = bool(kwargs.pop('remember_me'))
            try:
                ticket.known_device_info = BrowserDeviceInfo.from_public(
                    this_device, current_app.known_device_db.app_secret_box, remember_me
                )
            except:
                logger.exception("Couldn't parse the this_device supplied")
                logger.debug(f'Extra debug: Known device: {this_device}')
                pass

        kwargs['ticket'] = ticket
        return f(*args, **kwargs)

    return require_ticket_decorator


def uses_sso_session(f):
    @wraps(f)
    def uses_sso_session_decorator(*args, **kwargs):
        """Decorator to supply the current SSO session, if one is found and still valid"""

        kwargs['sso_session'] = get_sso_session()
        return f(*args, **kwargs)

    return uses_sso_session_decorator


def _flux_error(msg: IdPMsg):
    response_data = FluxFailResponse(request, payload={'error': msg, 'csrf_token': session.get_csrf_token()})
    return jsonify(response_data.to_dict())
