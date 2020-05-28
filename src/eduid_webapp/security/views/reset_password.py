# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from functools import wraps

from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_babel import gettext as _
from marshmallow import ValidationError

from eduid_common.api.decorators import require_user
from eduid_common.api.exceptions import MailTaskFailed, MsgTaskFailed
from eduid_common.api.helpers import check_magic_cookie
from eduid_common.session import session
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_userdb.security.state import PasswordResetEmailAndPhoneState, PasswordResetEmailState

from eduid_webapp.security.app import current_security_app as current_app
from eduid_webapp.security.helpers import (
    generate_suggested_password,
    get_extra_security_alternatives,
    get_zxcvbn_terms,
    mask_alternatives,
    reset_user_password,
    send_password_reset_mail,
    send_verify_phone_code,
    verify_email_address,
    verify_phone_number,
)
from eduid_webapp.security.schemas import (
    ResetPasswordEmailSchema,
    ResetPasswordExtraSecuritySchema,
    ResetPasswordNewPasswordSchema,
    ResetPasswordVerifyPhoneNumberSchema,
)

__author__ = 'lundberg'


reset_password_views = Blueprint('reset_password', __name__, url_prefix='/reset-password', template_folder='templates')


def require_state(f):
    @wraps(f)
    def require_state_decorator(*args, **kwargs):
        email_code = kwargs.pop('email_code')
        mail_expiration_time = current_app.config.email_code_timeout
        sms_expiration_time = current_app.config.phone_code_timeout
        try:
            state = current_app.password_reset_state_db.get_state_by_email_code(email_code)
            current_app.logger.debug(f'Found state using email_code {email_code}: {state}')
        except DocumentDoesNotExist:
            current_app.logger.info('State not found: {}'.format(email_code))
            view_context = {
                'heading': _('404 Not found'),
                'text': _('The requested state can not be found.'),
                'retry_url': url_for('reset_password.reset_password'),
                'retry_url_txt': _('Reset your password'),
            }
            return render_template('error.jinja2', view_context=view_context)

        if state.email_code.is_expired(mail_expiration_time):
            current_app.logger.info('State expired: {}'.format(email_code))
            view_context = {
                'heading': _('Link expired'),
                'text': _('The password reset link has expired.'),
                'retry_url': url_for('reset_password.reset_password'),
                'retry_url_txt': _('Reset your password'),
            }
            return render_template('error.jinja2', view_context=view_context)

        if isinstance(state, PasswordResetEmailAndPhoneState) and state.phone_code.is_expired(sms_expiration_time):
            current_app.logger.info('Phone code expired for state: {}'.format(email_code))
            # Revert the state to EmailState to allow the user to choose extra security again
            current_app.password_reset_state_db.remove_state(state)
            state = PasswordResetEmailState(
                eppn=state.eppn, email_address=state.email_address, email_code=state.email_code
            )
            current_app.password_reset_state_db.save(state)
            view_context = {
                'heading': _('SMS code expired'),
                'text': _('The phone verification has expired.'),
                'retry_url': url_for('reset_password.choose_extra_security', email_code=state.email_code.code),
                'retry_url_txt': _('Resend code or try another way'),
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
        try:
            form = ResetPasswordEmailSchema().load(request.form)
        except ValidationError as e:
            current_app.logger.error(e)
            view_context['errors'] = e.messages
        else:
            if session.get_csrf_token() == form['csrf']:
                current_app.logger.info('Trying to send password reset email to {}'.format(form['email']))
                try:
                    send_password_reset_mail(form['email'])
                except MailTaskFailed as e:
                    current_app.logger.error('Sending e-mail failed: {}'.format(e))
                    view_context = {
                        'heading': _('Temporary technical problem'),
                        'text': _('Please try again.'),
                        'retry_url': url_for('reset_password.reset_password'),
                        'retry_url_txt': _('Try again'),
                    }
                    return render_template('error.jinja2', view_context=view_context)
                view_context['form_post_success'] = True
                view_context['text'] = ''

    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password.jinja2', view_context=view_context)


@reset_password_views.route('/email/<email_code>', methods=['GET'])
@require_state
def email_reset_code(state):
    current_app.logger.info('Password reset: email_reset_code {}'.format(request.method))
    if verify_email_address(state):
        current_app.logger.info('Redirecting user to extra security view')
        return redirect(url_for('reset_password.choose_extra_security', email_code=state.email_code.code))

    current_app.logger.info('Could not validate email code for {}'.format(state.eppn))
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
    if not state.email_code.is_verified:
        current_app.logger.info('User {} has not verified their email address'.format(state.eppn))
        view_context = {
            'heading': _('Email address not validated'),
            'text': _('Please use the password reset link that you have in your email.'),
        }
        return render_template('error.jinja2', view_context=view_context)

    if request.method == 'POST':
        try:
            form = ResetPasswordExtraSecuritySchema().load(request.form)
        except ValidationError as e:
            current_app.logger.error(e)
            view_context['errors'] = e.messages
        else:
            if session.get_csrf_token() == form['csrf']:
                if form.get('no_extra_security'):
                    current_app.logger.info('Redirecting user to reset password with NO extra security')
                    current_app.stats.count(name='reset_password_no_extra_security')
                    return redirect(url_for('reset_password.new_password', email_code=state.email_code.code))
                if form.get('phone_number_index'):
                    phone_number_index = int(form.get('phone_number_index'))
                    phone_number = state.extra_security['phone_numbers'][phone_number_index]
                    current_app.logger.info('Trying to send password reset sms to user {}'.format(state.eppn))
                    try:
                        send_verify_phone_code(state, phone_number)
                    except MsgTaskFailed as e:
                        current_app.logger.error('Sending sms failed: {}'.format(e))
                        view_context = {
                            'heading': _('Temporary technical problem'),
                            'text': _('Please try again.'),
                            'retry_url': url_for(
                                'reset_password.choose_extra_security', email_code=state.email_code.code
                            ),
                            'retry_url_txt': _('Try again'),
                        }
                        return render_template('error.jinja2', view_context=view_context)
                    current_app.logger.info('Redirecting user to verify phone number view')
                    current_app.stats.count(name='reset_password_extra_security_phone')
                    return redirect(
                        url_for('reset_password.extra_security_phone_number', email_code=state.email_code.code)
                    )

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
    if not alternatives:
        # The user has no options for extra security, redirect to setting a new password
        return redirect(url_for('reset_password.new_password', email_code=state.email_code.code))
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
        try:
            form = ResetPasswordVerifyPhoneNumberSchema().load(request.form)
        except ValidationError as e:
            current_app.logger.error(e)
            view_context['errors'] = e.messages
        else:
            if session.get_csrf_token() == form['csrf']:
                current_app.logger.info('Trying to verify phone code')

                phone_code = form.get('phone_code', '')

                if phone_code == state.phone_code.code:
                    if not verify_phone_number(state):
                        current_app.logger.info('Could not validated phone code for {}'.format(state.eppn))
                        view_context = {
                            'heading': _('Temporary technical problem'),
                            'text': _('Please try again.'),
                            'retry_url': url_for(
                                'reset_password.choose_extra_security', email_code=state.email_code.code
                            ),
                            'retry_url_txt': _('Try again'),
                        }
                        return render_template('error.jinja2', view_context=view_context)
                    current_app.logger.info('Phone code verified redirecting user to set password view')
                    current_app.stats.count(name='reset_password_extra_security_phone_success')
                    return redirect(url_for('reset_password.new_password', email_code=state.email_code.code))
                view_context['form_post_fail_msg'] = _('Invalid code. Please try again.')
    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_verify_phone.jinja2', view_context=view_context)


@reset_password_views.route('/new-password/<email_code>', methods=['GET', 'POST'])
@require_state
def new_password(state):
    current_app.logger.info('Password reset: new_password {}'.format(request.method))
    view_context = {
        'heading': _('New password'),
        'text': _(
            '''
            Please choose a new password for your eduID account. A strong password has been generated for you.
            You can accept the generated password by clicking "Change password" or you can opt to choose your
            own password by clicking "Custom Password".
        '''
        ),
        'action': url_for('reset_password.new_password', email_code=state.email_code.code),
        'csrf_token': session.get_csrf_token(),
        'active_pane': 'generated',
        'zxcvbn_terms': json.dumps(get_zxcvbn_terms(state.eppn)),
        'errors': [],
    }
    if request.method == 'POST':
        min_entropy = current_app.config.password_entropy
        try:
            form = ResetPasswordNewPasswordSchema(
                zxcvbn_terms=view_context['zxcvbn_terms'], min_entropy=int(min_entropy)
            ).load(request.form)
            current_app.logger.debug(form)
        except ValidationError as e:
            current_app.logger.error(e)
            view_context['errors'] = e.messages
            view_context['active_pane'] = 'custom'
        else:
            if session.get_csrf_token() == form['csrf']:
                if form.get('use_generated_password'):
                    password = state.generated_password
                    current_app.logger.info('Generated password used')
                    current_app.stats.count(name='reset_password_generated_password_used')
                else:
                    password = form.get('custom_password')
                    current_app.logger.info('Custom password used')
                    current_app.stats.count(name='reset_password_custom_password_used')
                current_app.logger.info('Resetting password for user {}'.format(state.eppn))
                reset_user_password(state, password)
                current_app.logger.info('Password reset done removing state for user {}'.format(state.eppn))
                current_app.password_reset_state_db.remove_state(state)
                view_context['form_post_success'] = True
                view_context['login_url'] = current_app.config.eduid_site_url
                return render_template('reset_password_new_password.jinja2', view_context=view_context)

    # Generate a random good password
    # TODO: Hash the password using VCCSPasswordFactor before saving it to db
    state.generated_password = generate_suggested_password()
    view_context['generated_password'] = state.generated_password
    current_app.password_reset_state_db.save(state)

    view_context['csrf_token'] = session.new_csrf_token()
    return render_template('reset_password_new_password.jinja2', view_context=view_context)


@reset_password_views.route('/get-email-code', methods=['GET'])
def get_email_code():
    """
    Backdoor to get the email verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.config):
            eppn = request.args.get('eppn')
            state = current_app.password_reset_state_db.get_state_by_eppn(eppn)
            return state.email_code.code
    except Exception:
        current_app.logger.exception(
            "Someone tried to use the backdoor to get the email verification code for a password reset"
        )

    abort(400)


@reset_password_views.route('/get-phone-code', methods=['GET'])
def get_phone_code():
    """
    Backdoor to get the phone verification code in the staging or dev environments
    """
    try:
        if check_magic_cookie(current_app.config):
            eppn = request.args.get('eppn')
            state = current_app.password_reset_state_db.get_state_by_eppn(eppn)
            return state.phone_code.code
    except Exception:
        current_app.logger.exception(
            "Someone tried to use the backdoor to get the SMS verification code for a password reset"
        )

    abort(400)
