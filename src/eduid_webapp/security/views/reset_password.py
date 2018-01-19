# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, session, request, render_template, current_app, url_for
from flask_babel import gettext as _
from eduid_common.api.utils import save_and_sync_user
from eduid_webapp.security.schemas import ResetPasswordEmailSchema


__author__ = 'lundberg'


reset_password_views = Blueprint('reset_password', __name__, url_prefix='/reset-password', template_folder='templates')


@reset_password_views.route('/', methods=['GET'])
def reset_password():
    current_app.logger.debug('Password reset')
    return render_template('reset_password.jinja2')


@reset_password_views.route('/email', methods=['GET', 'POST'])
def reset_password_email():
    form_context = {
        'heading': _('Reset password with email'),
        'text': _('When using this method you have to verify your account again.'),
        'action': url_for('reset_password.reset_password_email'),
        'csrf_token': session.get_csrf_token(),
        'errors': [],
    }

    current_app.logger.debug('Password reset: email')
    if request.method == 'POST':
        current_app.logger.debug('Got POST: {}'.format(request.form))
        form = ResetPasswordEmailSchema().load(request.form)
        current_app.logger.debug('Unmarshalled form data: {}'.format(form))
        if not form.errors and session.get_csrf_token() == form.data['csrf']:
            return str('success')
        form_context['errors'] = form.errors
    form_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_email.jinja2', form_context=form_context)


@reset_password_views.route('/phone-and-email', methods=['GET', 'POST'])
def reset_password_phone_and_email():
    form_context = {
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
        if not form.errors and form_context['csrf_token'] == form.data['csrf']:
            return str('success')
        form_context['errors'] = form.errors
    form_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_email.jinja2', form_context=form_context)



