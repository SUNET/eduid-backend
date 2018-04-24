# -*- coding: utf-8 -*-

from __future__ import absolute_import

from functools import wraps
from flask import Blueprint, session, request, render_template, current_app, url_for, redirect
from flask.helpers import NotFound
from flask_babel import gettext as _
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.security.schemas import ResetPasswordEmailSchema, ResetPasswordExtraSecuritySchema
from eduid_webapp.security.schemas import ResetPasswordVerifyPhoneNumberSchema
from eduid_webapp.security.helpers import send_password_reset_mail, get_extra_security_alternatives, mask_alternatives
from eduid_webapp.security.helpers import send_verify_phone_code


__author__ = 'lundberg'


reset_password_views = Blueprint('reset_password', __name__, url_prefix='/reset-password', template_folder='templates')


def require_state(f):
    @wraps(f)
    def require_state_decorator(*args, **kwargs):
        email_code = kwargs.pop('email_code')
        expiration_time = current_app.config['EMAIL_CODE_TIMEOUT_MINUTES'] / 60  # expiration_time in hours
        try:
            state = current_app.password_reset_state_db.get_state_by_email_code(email_code)
        except DocumentDoesNotExist:
            current_app.logger.info('State not found: {}'.format(email_code))
            view_context = {
                'heading': _('404 Not found'),
                'text': _('The requested state can not be found.'),
            }
            return render_template('error.jinja2', view_context=view_context)

        if state.email_code.is_expired(expiration_time):
            current_app.logger.info('State expired: {}'.format(email_code))
            view_context = {
                'heading': _('Link expired'),
                'text': _('The password reset link has expired.'),
            }
            return render_template('error.jinja2', view_context=view_context)

        kwargs['state'] = state
        return f(*args, **kwargs)
    return require_state_decorator


@reset_password_views.route('/', methods=['GET', 'POST'])
def reset_password():
    current_app.logger.info('Password reset: reset_password {}'.format(request.method))
    view_context = {
        'heading': _('Reset password'),
        'text': _('Enter an email address registered to your account below'),
        'action': url_for('reset_password.reset_password'),
        'csrf_token': session.get_csrf_token(),
        'form_post_success': False,
        'form_post_success_msg': _('Reset password message sent. Check your email to continue.'),
        'errors': [],
    }
    if request.method == 'POST':
        form = ResetPasswordEmailSchema().load(request.form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            current_app.logger.info('Trying to send password reset email to {}'.format(form.data['email']))
            send_password_reset_mail(form.data['email'])
            view_context['form_post_success'] = True
            view_context['text'] = ''
        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password.jinja2', view_context=view_context)


@reset_password_views.route('/email/<email_code>', methods=['GET'])
@require_state
def email_reset_code(state):
    current_app.logger.info('Password reset: email_reset_code {}'.format(request.method))
    state.email_code.is_used = True
    current_app.password_reset_state_db.save(state)
    current_app.logger.info('Email code ({}) marked as used for {}'.format(state.email_code.code, state.eppn))
    current_app.logger.info('Redirecting user to extra security view')
    return redirect(url_for('reset_password.choose_extra_security', email_code=state.email_code.code))


@reset_password_views.route('/extra-security/<email_code>', methods=['GET', 'POST'])
@require_state
def choose_extra_security(state):
    current_app.logger.info('Password reset: choose_extra_security {}'.format(request.method))
    view_context = {
        'heading': _('Extra security'),
        'text': _('Choose an option to enhance the security'),
        'action': url_for('reset_password.choose_extra_security', email_code=state.email_code.code),
        'csrf_token': session.get_csrf_token(),
        'form_post_success': False,
        'errors': [],
    }

    # Check that the email code has been validated
    if not state.email_code.is_used:
        current_app.logger.info('Email code not validated: {}'.format(state.email_code.code))
        view_context = {
            'heading': _('Email address not validated'),
            'text': _('Please use the password reset link that you have in your email.'),
        }
        return render_template('error.jinja2', view_context=view_context)

    if request.method == 'POST':
        form = ResetPasswordExtraSecuritySchema().load(request.form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            if form.data.get('no_extra_security'):
                current_app.logger.info('Redirecting user to reset password with NO extra security')
                # TODO
            if form.data.get('phone_number_index'):
                phone_number_index = int(form.data.get('phone_number_index'))
                phone_number = state.extra_security['phone_numbers'][phone_number_index]
                current_app.logger.info('Trying to send password reset sms to user {}'.format(state.eppn))
                send_verify_phone_code(state, phone_number)
                current_app.logger.info('Redirecting user to verify phone number view')
                return redirect(url_for('reset_password.verify_phone_number', email_code=state.email_code.code))

        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()

    try:
        alternatives = get_extra_security_alternatives(state.eppn)
        state.extra_security = alternatives
        current_app.password_reset_state_db.save(state)
        view_context['security_alternatives'] = mask_alternatives(alternatives)
    except DocumentDoesNotExist:
        current_app.logger.error('User {} not found'.format(state.eppn))
        view_context = {
            'heading': _('Something went wrong'),
            'text': _('Please restart the password reset procedure.'),
        }
        return render_template('error.jinja2', view_context=view_context)
    return render_template('reset_password_extra_security.jinja2', view_context=view_context)


@reset_password_views.route('/extra-security/phone/<email_code>', methods=['GET', 'POST'])
@require_state
def verify_phone_number(state):
    current_app.logger.info('Password reset: verify_phone_number {}'.format(request.method))
    view_context = {
        'heading': _('Verify phone number'),
        'text': _('Enter the code you received via SMS'),
        'action': url_for('reset_password.verify_phone_number', email_code=state.email_code.code),
        'csrf_token': session.get_csrf_token(),
        'errors': [],
    }
    if request.method == 'POST':
        form = ResetPasswordVerifyPhoneNumberSchema().load(request.form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            current_app.logger.info('Trying to verify phone code')
            if form.data.phone_code == state.phone_code.code:
                pass

        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password.jinja2', view_context=view_context)
