# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, session, request, render_template, current_app, url_for, redirect
from flask.helpers import NotFound
from flask_babel import gettext as _
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.security.schemas import ResetPasswordEmailSchema, ResetPasswordExtraSecuritySchema
from eduid_webapp.security.helpers import send_password_reset_mail, get_extra_security_alternatives


__author__ = 'lundberg'


reset_password_views = Blueprint('reset_password', __name__, url_prefix='/reset-password', template_folder='templates')


@reset_password_views.route('/', methods=['GET', 'POST'])
def reset_password_email():
    view_context = {
        'heading': _('Reset password'),
        'text': _('Enter an email address registered to your account below.'),
        'action': url_for('reset_password.reset_password_email'),
        'csrf_token': session.get_csrf_token(),
        'form_post_success': False,
        'form_post_success_msg': _('Reset password message sent. Check your email to continue.'),
        'errors': [],
    }

    current_app.logger.info('Password reset: email')
    if request.method == 'POST':
        form = ResetPasswordEmailSchema().load(request.form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            current_app.logger.info('Trying to send password reset email')
            send_password_reset_mail(form.data['email'])
            view_context['form_post_success'] = True
            view_context['text'] = ''
        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_email.jinja2', view_context=view_context)


@reset_password_views.route('/phone-and-email', methods=['GET', 'POST'])
def reset_password_phone_and_email():
    view_context = {
        'heading': _('Reset password with email and SMS code'),
        'action': url_for('reset_password.reset_password_phone_and_email'),
        'csrf_token': session.get_csrf_token(),
        'errors': [],
    }

    current_app.logger.debug('Password reset: phone and email')
    if request.method == 'POST':
        current_app.logger.debug('Got POST: {}'.format(request.form))
        form = ResetPasswordEmailSchema().load(request.form)
        current_app.logger.debug('Unmarshalled form data: {}'.format(form))
        if not form.errors and view_context['csrf_token'] == form.data['csrf']:
            return str('success')
        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_email.jinja2', view_context=view_context)


@reset_password_views.route('/email/<email_code>', methods=['GET'])
def email_reset_code(email_code):
    try:
        state = current_app.password_reset_state_db.get_state_by_email_code(email_code)
    except DocumentDoesNotExist:
        current_app.logger.info('State not found: {}'.format(email_code))
        view_context = {
            'heading': _('404 Not found'),
            'text': _('The requested state can not be found.'),
        }
        return render_template('error.jinja2', view_context=view_context)
    expiration_time = current_app.config['EMAIL_CODE_TIMEOUT_MINUTES'] / 60  # expiration_time in hours
    if state.email_code.is_used or state.email_code.is_expired(expiration_time):
        current_app.logger.info('State expired: {}'.format(email_code))
        view_context = {
            'heading': _('Link expired'),
            'text': _('The password reset link has expired.'),
        }
        return render_template('error.jinja2', view_context=view_context)
    state.email_code.is_used = True
    current_app.password_reset_state_db.save(state)
    current_app.logger.info('Email code ({}) marked as used for {}'.format(email_code, state.eppn))
    current_app.logger.info('Redirecting user to extra security view')
    return redirect(url_for('reset_password.choose_extra_security', email_code=email_code))


@reset_password_views.route('/extra-security/<email_code>', methods=['GET', 'POST'])
def choose_extra_security(email_code):
    current_app.logger.info('Password reset: choose_extra_security')
    view_context = {
        'heading': _('Extra security'),
        'text': _('Choose an option to enhance the security.'),
        'action': url_for('reset_password.choose_extra_security', email_code=email_code),
        'csrf_token': session.get_csrf_token(),
        'form_post_success': False,
        'errors': [],
    }

    try:
        state = current_app.password_reset_state_db.get_state_by_email_code(email_code)
    except DocumentDoesNotExist:
        current_app.logger.info('State not found: {}'.format(email_code))
        view_context = {
            'heading': _('404 Not found'),
            'text': _('The requested state can not be found.'),
        }
        return render_template('error.jinja2', view_context=view_context)

    if request.method == 'POST':
        form = ResetPasswordExtraSecuritySchema().load(request.form)
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            if form.data.get('no_extra_security'):
                current_app.logger.info('Redirecting user to reset password with NO extra security')
                # TODO
            if form.data.get('phone_number'):
                current_app.logger.info('Creating PasswordResetEmailAndPhoneState')
                current_app.logger.debug('User: {}. Phone number: {}. State: {}'.format(state.eppn,
                                                                                        form.data.get('phone_number'),
                                                                                        email_code))
                current_app.logger.info('Redirecting user to verify phone number view')
                # TODO

        view_context['errors'] = form.errors
    view_context['csrf_token'] = session.new_csrf_token()

    try:
        alternatives = get_extra_security_alternatives(state.eppn)
    except DocumentDoesNotExist:
        current_app.logger.error('User {} not found'.format(state.eppn))
        view_context = {
            'heading': _('Something went wrong'),
            'text': _('Please restart the password reset request.'),
        }
        return render_template('error.jinja2', view_context=view_context)
    view_context['security_alternatives'] = alternatives
    return render_template('reset_password_extra_security.jinja2', view_context=view_context)
