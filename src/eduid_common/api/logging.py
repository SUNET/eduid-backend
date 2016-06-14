# -*- coding: utf-8 -*-

from __future__ import absolute_import

import logging
from logging.handlers import RotatingFileHandler
from eduid_common.api.exceptions import BadConfiguration

__author__ = 'lundberg'


def rotating(app, root_logger):
    """
    :param app: Flask app
    :param root_logger: Catch all logger object

    :type app: flask.app.Flask
    :type root_logger: logging.Logger

    :return: Flask app with rotating log handler
    :rtype: flask.app.Flask

    Override the following config settings if needed:
    LOG_TYPE = ['rotating']
    LOG_FILE = None
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_LEVEL = 'INFO'
    LOG_MAX_BYTES = 1000000
    LOG_BACKUP_COUNT = 10
    """
    app.config.setdefault('LOG_FILE', None)
    app.config.setdefault('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    app.config.setdefault('LOG_MAX_BYTES', 1000000)  # 1 MB
    app.config.setdefault('LOG_BACKUP_COUNT', 10)  # 10 x 1 MB

    if app.config['LOG_FILE']:
        try:
            handler = RotatingFileHandler(app.config['LOG_FILE'], maxBytes=app.config['LOG_MAX_BYTES'],
                                          backupCount=app.config['LOG_BACKUP_COUNT'])
            handler.setLevel(app.config['LOG_LEVEL'])
            formatter = logging.Formatter(app.config['LOG_FORMAT'])
            handler.setFormatter(formatter)
            root_logger.addHandler(handler)
            app.logger.info('Rotating log handler initiated')
        except AttributeError as e:
            raise BadConfiguration(e.message)
    return app


def init_logging(app):
    """
    :param app: Flask app
    :type app: flask.app.Flask
    :return: Flask app with log handlers
    :rtype: flask.app.Flask
    """
    app.config.setdefault('LOG_LEVEL', 'INFO')
    app.config.setdefault('LOG_TYPE', ['rotating'])
    root_logger = logging.getLogger()
    root_logger.setLevel(app.config['LOG_LEVEL'])

    for log_type in app.config['LOG_TYPE']:
        init_handler = globals().get(log_type)
        if init_handler:
            app = init_handler(app, root_logger)
    return app


