# -*- coding: utf-8 -*-

from __future__ import absolute_import

import logging
import six
import json
from functools import wraps
from nacl import secret, encoding, exceptions
from string import Template

from eduid_common.config.parsers.exceptions import SecretKeyException

__author__ = 'lundberg'


def decrypt(f):
    @wraps(f)
    def decrypt_decorator(*args, **kwargs):
        config_dict = f(*args, **kwargs)
        decrypted_config_dict = decrypt_config(config_dict)
        return decrypted_config_dict

    return decrypt_decorator


def read_secret_key(key_name):
    """
    :param key_name: Key file name
    :type key_name: six.string_types
    :return: 32 bytes of secret data
    :rtype: bytes
    """
    sanitized_key_name = "".join([c for c in key_name if c.isalpha() or c.isdigit() or c == '_'])
    fp = '/run/secrets/{}'.format(sanitized_key_name)
    with open(fp) as f:
        return encoding.URLSafeBase64Encoder.decode(f.readline())


def init_secret_box(key_name=None, secret_key=None):
    """
    :param key_name: Key file name
    :type key_name: six.string_types
    :param secret_key: 32 bytes of secret data
    :type secret_key: bytes
    :return: SecretBox
    :rtype: SecretBox
    """
    if not secret_key:
        try:
            secret_key = read_secret_key(key_name)
        except IOError as e:
            raise SecretKeyException(str(e))
    return secret.SecretBox(secret_key)


def decrypt_config(config_dict):
    """
    :param config_dict: Configuration dictionary
    :type config_dict: dict
    :return: Configuration dictionary
    :rtype: dict
    """
    boxes = {}
    for key, value in config_dict.items():
        if key.endswith('_ENCRYPTED'):
            decrypted = False
            for item in value:
                key_name = item['key_name']
                encrypted_value = item['value']

                if not boxes.get(key_name):
                    try:
                        boxes[key_name] = init_secret_box(key_name=key_name)
                    except SecretKeyException as e:
                        logging.debug(e)
                        continue  # Try next key
                try:
                    if six.PY2:
                        encrypted_value = encrypted_value.encode('ascii')
                        decrypted_value = boxes[key_name].decrypt(encrypted_value,
                                                                  encoder=encoding.URLSafeBase64Encoder)
                    else:
                        encrypted_value = bytes(encrypted_value, 'ascii')
                        decrypted_value = boxes[key_name].decrypt(encrypted_value,
                                                                  encoder=encoding.URLSafeBase64Encoder).decode('ascii')

                    config_dict[key.replace('_ENCRYPTED', '')] = decrypted_value
                    del config_dict[key]
                    decrypted = True
                    break  # Decryption successful, do not try any more keys
                except exceptions.CryptoError as e:
                    logging.debug(e)
                    continue  # Try next key
            if not decrypted:
                logging.error('Failed to decrypt {}:{}'.format(key, value))
    return config_dict


def interpolate(f):
    @wraps(f)
    def interpolation_decorator(*args, **kwargs):
        config_dict = f(*args, **kwargs)
        interpolated_config_dict = interpolate_config(config_dict)
        return interpolated_config_dict

    return interpolation_decorator


def interpolate_config(config_dict):
    """
    :param config_dict: Configuration dictionary
    :type config_dict: dict
    :return: Configuration dictionary
    :rtype: dict
    """
    template = Template(json.dumps(config_dict))
    string_config = template.safe_substitute(config_dict)
    return json.loads(string_config)
