# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.app import eduid_init_app
from eduid_common.api.utils import urlappend
from eduid_userdb.support import db
from flask import url_for


def register_template_funcs(app):

    @app.template_filter('datetimeformat')
    def datetimeformat(value, format='%Y-%m-%d %H:%M %Z'):
        if not value:
            return ''
        return value.strftime(format)

    @app.template_global()
    def static_url(filename):
        url = app.config.get('STATIC_URL')

        if url:
            return urlappend(url, filename)
        # If STATIC_URL is not set use Flask default
        return url_for('static', filename=filename)


def support_init_app(name, config):
    """
    Create an instance of an eduid support app.

    First, it will load the configuration from support.settings.common
    then any settings given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    and finally all needed blueprints will be registered with it.

    :param name: The name of the instance, it will affect the configuration loaded.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config)
    if app.config.get('TOKEN_SERVICE_URL_LOGOUT') is None:
        app.config['TOKEN_SERVICE_URL_LOGOUT'] = urlappend(app.config['TOKEN_SERVICE_URL'], 'logout')
    app.config.update(config)

    from eduid_webapp.support.views import support_views
    app.register_blueprint(support_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    app.support_user_db = db.SupportUserDB(app.config['MONGO_URI'])
    app.support_authn_db = db.SupportAuthnInfoDB(app.config['MONGO_URI'])
    app.support_verification_db = db.SupportVerificationsDB(app.config['MONGO_URI'])
    app.support_proofing_log_db = db.SupportProofingLogDB(app.config['MONGO_URI'])
    app.support_dashboard_db = db.SupportDashboardUserDB(app.config['MONGO_URI'])
    app.support_signup_db = db.SupportSignupUserDB(app.config['MONGO_URI'])
    app.support_actions_db = db.SupportActionsDB(app.config['MONGO_URI'])
    app.support_letter_proofing_db = db.SupportLetterProofingDB(app.config['MONGO_URI'])
    app.support_oidc_proofing_db = db.SupportOidcProofingDB(app.config['MONGO_URI'])

    register_template_funcs(app)

    app.logger.info('Init {} app...'.format(name))

    return app
