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
#@login_required
def index(logged_in_user=None):
    if request.method == 'POST':
        search_query = request.form.get('query')
        lookup_users = current_app.support_user_db.search_users(request.form.get('query'))
        users = list()

        if len(lookup_users) == 0:
            # If no users where found in the central database look in signup database
            lookup_users = current_app.support_signup_db.get_user_by_mail(search_query, return_list=True,
                                                                          include_unconfirmed=True)
            if len(lookup_users) == 0:
                current_app.logger.warn('Support personnel: {!r} searched for {!r} without any match found'
                                        .format(logged_in_user, search_query))
                return render_template('index.html', error="No users matched the search query")

        current_app.logger.info('Support personnel: {!r} searched for {!r}'.format(logged_in_user, search_query))

        for user in lookup_users:
            user_data = dict()
            # Users
            user_data['user'] = current_app.support_user_db.get_user_by_id(user_id=user['user_id'],
                                                                           raise_on_missing=False)
            user_data['dashboard_user'] = current_app.support_dashboard_db.get_user_by_id(user_id=user['user_id'],
                                                                                          raise_on_missing=False)
            user_data['signup_user'] = current_app.support_signup_db.get_user_by_id(user_id=user['user_id'],
                                                                                    raise_on_missing=False)
            # Aux data
            user_data['authn'] = current_app.support_authn_db.get_authn_info(user_id=user['user_id'])
            user_data['verifications'] = current_app.support_verification_db.get_verifications(user_id=user['user_id'])

            user_data['actions'] = current_app.support_actions_db.get_actions(user_id=user['user_id'])
            user_data['letter_proofing'] = current_app.support_letter_proofing_db.get_proofing_state(
                eppn=user['eduPersonPrincipalName'])
            users.append(user_data)

        return render_template('index.html', users=users)
    else:
        return render_template('index.html')
