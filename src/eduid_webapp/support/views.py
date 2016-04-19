# -*- coding: utf-8 -*-
from __future__ import absolute_import
from functools import wraps

from flask import Blueprint, current_app, request, session, abort

support_views = Blueprint('support', __name__, url_prefix='')

support_personnel = ['govaf-hovof', 'nivav-bobol']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If the application is running at a subdomain that is allowed to
        # read the dashboard cookie, for example support.dashboard.docker,
        # then we can verify if the session in the cookie corresponds
        # to the session in Redis if we share the same HMAC-key.
        # Although the cookie is named sessid, it is actually a token
        # that contains the session id and a HMAC signature.
        session_token = request.cookies.get('sessid', None)

        if session_token is None:
            abort(403)

        try:
            session = current_app.session_interface.manager.get_session(token=session_token)
            # We are probably only interested in KeyError,
            # but any error should be considered as an
            # unauthorized request.
        except:
            abort(403)

        session_user = session.get('user_eppn', None)

        # If the logged in user is whitelisted then we
        # pass on the request to the decorated view.
        if session_user in support_personnel:
            return f(*args, **kwargs)

        # Anything else is considered as an unauthorized request
        abort(403)
    return decorated_function

@support_views.route('/', methods=['GET'])
@login_required
def index():
    # TODO Add a template with a form and use the userdb code to lookup a user
    return "Logged in as authorized personnel"
