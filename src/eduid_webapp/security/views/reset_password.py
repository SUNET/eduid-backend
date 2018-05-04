# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from functools import wraps
from flask import Blueprint, session, request, render_template, current_app, url_for, redirect
from flask_babel import gettext as _
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_webapp.security.schemas import ResetPasswordEmailSchema, ResetPasswordExtraSecuritySchema
from eduid_webapp.security.schemas import ResetPasswordVerifyPhoneNumberSchema, ResetPasswordNewPasswordSchema
from eduid_webapp.security.helpers import send_password_reset_mail, get_extra_security_alternatives, mask_alternatives
from eduid_webapp.security.helpers import send_verify_phone_code, verify_email_address, verify_phone_number
from eduid_webapp.security.helpers import generate_suggested_password, get_zxcvbn_terms, reset_user_password


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
                'retry_url': url_for('reset_password.reset_password'),
                'retry_url_txt': _('Reset your password'),
            }
            return render_template('error.jinja2', view_context=view_context)

        if state.email_code.is_expired(expiration_time):
            current_app.logger.info('State expired: {}'.format(email_code))
            view_context = {
                'heading': _('Link expired'),
                'text': _('The password reset link has expired.'),
                'retry_url': url_for('reset_password.reset_password'),
                'retry_url_txt': _('Reset your password'),
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
    if verify_email_address(state):
        current_app.logger.info('Redirecting user to extra security view')
        return redirect(url_for('reset_password.choose_extra_security', email_code=state.email_code.code))

    current_app.logger.info('Could not validated email code for {}'.format(state.eppn))
    view_context = {
        'heading': _('Temporary technical problem'),
        'text': _('Please try again.'),
        'retry_url': url_for('reset_password.reset_password'),
        'retry_url_txt': _('Reset your password'),
    }
    return render_template('error.jinja2', view_context=view_context)


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
    if not state.email_code.verified:
        current_app.logger.info('User {} has not verified their email address'.format(state.eppn))
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
                return redirect(url_for('reset_password.new_password', email_code=state.email_code.code))
            if form.data.get('phone_number_index'):
                phone_number_index = int(form.data.get('phone_number_index'))
                phone_number = state.extra_security['phone_numbers'][phone_number_index]
                current_app.logger.info('Trying to send password reset sms to user {}'.format(state.eppn))
                send_verify_phone_code(state, phone_number)
                current_app.logger.info('Redirecting user to verify phone number view')
                return redirect(url_for('reset_password.extra_security_phone_number', email_code=state.email_code.code))

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
            'retry_url': url_for('reset_password.reset_password'),
            'retry_url_txt': _('Reset your password'),
        }
        return render_template('error.jinja2', view_context=view_context)
    return render_template('reset_password_extra_security.jinja2', view_context=view_context)


@reset_password_views.route('/extra-security/phone/<email_code>', methods=['GET', 'POST'])
@require_state
def extra_security_phone_number(state):
    current_app.logger.info('Password reset: verify_phone_number {}'.format(request.method))
    view_context = {
        'heading': _('Verify phone number'),
        'text': _('Enter the code you received via SMS'),
        'action': url_for('reset_password.extra_security_phone_number', email_code=state.email_code.code),
        'form_post_fail_msg': None,
        'retry_url': url_for('reset_password.choose_extra_security', email_code=state.email_code.code),
        'retry_url_txt': _('Resend code or try another way'),
        'csrf_token': session.get_csrf_token(),
        'errors': [],
    }
    if request.method == 'POST':
        form = ResetPasswordVerifyPhoneNumberSchema().load(request.form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            current_app.logger.info('Trying to verify phone code')
            if form.data.get('phone_code', '') == state.phone_code.code:
                if not verify_phone_number(state):
                    current_app.logger.info('Could not validated phone code for {}'.format(state.eppn))
                    view_context = {
                        'heading': _('Temporary technical problem'),
                        'text': _('Please try again.'),
                        'retry_url': url_for('reset_password.choose_extra_security', email_code=state.email_code.code),
                        'retry_url_txt': _('Try again'),
                    }
                    return render_template('error.jinja2', view_context=view_context)
                current_app.logger.info('Phone code verified redirecting user to set password view')
                return redirect(url_for('reset_password.new_password', email_code=state.email_code.code))
            view_context['form_post_fail_msg'] = _('That was not the code we sent you. Please try again.')
        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_verify_phone.jinja2', view_context=view_context)


@reset_password_views.route('/new-password/<email_code>', methods=['GET', 'POST'])
@require_state
def new_password(state):
    current_app.logger.info('Password reset: new_password {}'.format(request.method))
    view_context = {
        'heading': _('New password'),
        'text': _('''
            Please choose a new password for your eduID account. A strong password has been generated for you.
            You can accept the generated password by clicking "Change password" or you can opt to choose your
            own password by clicking "Custom Password".
        '''),
        'action': url_for('reset_password.new_password', email_code=state.email_code.code),
        'csrf_token': session.get_csrf_token(),
        'active_pane': 'generated',
        'zxcvbn_terms': json.dumps(get_zxcvbn_terms(state.eppn)),
        'errors': [],
    }
    if request.method == 'POST':
        min_entropy = current_app.config['PASSWORD_ENTROPY']
        form = ResetPasswordNewPasswordSchema(
            zxcvbn_terms=view_context['zxcvbn_terms'], min_entropy=int(min_entropy)).load(request.form)
        current_app.logger.debug(form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            if form.data.get('use_generated_password'):
                password = state.generated_password
            else:
                password = form.data.get('custom_password')
            reset_user_password(state, password)

        view_context['errors'] = form.errors
        view_context['active_pane'] = 'custom'

    # Generate a random good password
    # TODO: Hash the password using VCCSPasswordFactor before saving it to db
    state.generated_password = generate_suggested_password()
    view_context['generated_password'] = state.generated_password
    current_app.password_reset_state_db.save(state)

    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_new_password.jinja2', view_context=view_context)
