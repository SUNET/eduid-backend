# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import Blueprint, render_template, request

from eduid_common.api.decorators import require_support_personnel
from eduid_userdb.exceptions import UserDoesNotExist, UserHasNotCompletedSignup, UserHasUnknownData
from eduid_userdb.support.models import SupportSignupUserFilter, SupportUserFilter

from eduid_webapp.support.app import current_support_app as current_app
from eduid_webapp.support.helpers import get_credentials_aux_data

support_views = Blueprint('support', __name__, url_prefix='', template_folder='templates')


@support_views.route('/', methods=['GET', 'POST'])
@require_support_personnel
def index(support_user):
    if request.method == 'POST':
        search_query = request.form.get('query')
        try:
            lookup_users = current_app.support_user_db.search_users(request.form.get('query'))
        except UserHasNotCompletedSignup:
            # Old bug where incomplete signup users where written to central db
            lookup_users = []
        users = list()

        if len(lookup_users) == 0:
            # If no users where found in the central database look in signup database
            lookup_users = current_app.support_signup_db.get_user_by_mail(
                search_query, raise_on_missing=False, return_list=True, include_unconfirmed=True
            )
            if len(lookup_users) == 0:
                user = current_app.support_signup_db.get_user_by_pending_mail_address(search_query)
                if user:
                    lookup_users = [user]
            if len(lookup_users) == 0:
                current_app.logger.warn(
                    'Support personnel: {!r} searched for {!r} without any match found'.format(
                        support_user, search_query
                    )
                )
                return render_template(
                    'index.html', support_user=support_user, error="No users matched the search query"
                )

        current_app.logger.info('Support personnel {} searched for {}'.format(support_user, search_query))
        for user in lookup_users:
            user_data = dict()
            user_dict = user.to_dict()
            # Extend credentials with last used timestamp
            user_dict['passwords'] = get_credentials_aux_data(user)
            # Filter out unwanted data from user object
            user_data['user'] = SupportUserFilter(user_dict)
            try:
                signup_user = current_app.support_signup_db.get_user_by_id(user_id=user.user_id)
                user_data['signup_user'] = SupportSignupUserFilter(signup_user.to_dict())
            except (UserHasUnknownData, UserDoesNotExist):
                # The user is in an old format or does not exist in the signup db
                user_data['signup_user'] = None

            # Aux data
            user_data['authn'] = current_app.support_authn_db.get_authn_info(user_id=user.user_id)
            user_data['proofing_log'] = current_app.support_proofing_log_db.get_entries(eppn=user.eppn)
            user_data['actions'] = current_app.support_actions_db.get_actions(user_id=user.user_id)
            user_data['letter_proofing'] = current_app.support_letter_proofing_db.get_proofing_state(eppn=user.eppn)
            user_data['oidc_proofing'] = current_app.support_oidc_proofing_db.get_proofing_state(eppn=user.eppn)
            user_data['email_proofings'] = current_app.support_email_proofing_db.get_proofing_states(eppn=user.eppn)
            user_data['phone_proofings'] = current_app.support_phone_proofing_db.get_proofing_states(eppn=user.eppn)
            users.append(user_data)

        return render_template('index.html', support_user=support_user, users=users, search_query=search_query)
    else:
        return render_template('index.html', support_user=support_user)
