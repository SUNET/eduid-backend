# -*- coding: utf-8 -*-

from __future__ import absolute_import

import base64
import logging
from functools import wraps
from os import environ
from nacl import secret, exceptions

__author__ = 'lundberg'


def decrypt(f):
    @wraps(f)
    def decrypt_decorator(*args, **kwargs):
        config_dict = f(*args, **kwargs)
        app_config_secret = environ.get('APP_CONFIG_SECRET')
        if not app_config_secret:
            logging.info('APP_CONFIG_SECRET not found. Will not try to decrypt config.')
            return config_dict
        decrypted_config_dict = decrypt_config(config_dict, app_config_secret)
        return decrypted_config_dict

    return decrypt_decorator


def decrypt_config(config_dict, app_config_secret):
    box = secret.SecretBox(app_config_secret)

    for key, value in config_dict.items():
        if key.endswith('_ENCRYPTED'):
            try:
                config_dict[key.replace('_ENCRYPTED', '')] = box.decrypt(base64.urlsafe_b64decode(value))
                del config_dict[key]
            except exceptions.CryptoError as e:
                logging.error(e)
    return config_dict
