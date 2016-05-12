# -*- coding: utf-8 -*-
from __future__ import absolute_import
from functools import wraps

from flask import Blueprint,\
    current_app,\
    request,\
    session,\
    abort,\
    render_template

from eduid_userdb.user import MailAddressList

support_views = Blueprint('support', __name__, url_prefix='')

# Add the support personnel eppn to this list
support_personnel = ['']

# This should probably be replaced with authn when it's ready
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
        # pass on the request to the decorated view
        # together with the eppn of the logged in user.
        if session_user in support_personnel:
            kwargs['logged_in_user'] = session_user
            return f(*args, **kwargs)

        # Anything else is considered as an unauthorized request
        abort(403)
    return decorated_function

@support_views.route('/', methods=['GET', 'POST'])
@login_required
def index(logged_in_user):
    if request.method == 'POST':
        search_query = request.form.get('query')
        lookup_users = current_app.support_user_db.search_users(request.form.get('query'))

        if len(lookup_users) == 0:
            current_app.logger.warn('Support personnel: {!r} searched for {!r} without any match found'
                                    .format(logged_in_user, search_query))
            return render_template('index.html', error="No users matched the search query")

        if len(lookup_users) > 1:
            current_app.logger.warn('Support personnel: {!r} searched for {!r}'
                                    ' and multiple users were returned'.format(logged_in_user, search_query))
            return render_template('index.html', error='Multiple users returned', users=lookup_users)

        # We are only dealing with one user that matched the search query
        user = lookup_users[0]
        lookup_authn = current_app.support_authn_db.get_authn_info(user_id=user.user_id)

        mail_addresses = user.mail_addresses.to_list_of_dicts()

        current_app.logger.info('Support personnel: {!r} searched for {!r}'.format(logged_in_user, search_query))

        return render_template('index.html', users=lookup_users,
                               authn=lookup_authn, mail_addresses=mail_addresses)
    else:
        return render_template('index.html')
