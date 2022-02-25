from flask import Blueprint

from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, success_response
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.schemas import NewDeviceRequestSchema, NewDeviceResponseSchema

known_device_views = Blueprint('known_device', __name__, url_prefix='')


@known_device_views.route('/new_device', methods=['POST'])
@UnmarshalWith(NewDeviceRequestSchema)
@MarshalWith(NewDeviceResponseSchema)
@require_ticket
def new_device(ticket: LoginContext) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- New Device ({ticket.request_ref}) ---')

    current_app.logger.debug(f'Current known device: {ticket.known_device}')
    if ticket.known_device:
        current_app.stats.count('login_new_device_replacing_existing')
    else:
        current_app.stats.count('login_new_device_minted')

    browser_info = current_app.known_device_db.create_new_state()

    return success_response(payload={'new_device': browser_info.shared})
