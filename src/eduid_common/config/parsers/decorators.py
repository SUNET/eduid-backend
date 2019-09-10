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
        secret_key = read_secret_key(key_name)
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
        if key.lower().endswith('_encrypted'):
            decrypted = False
            for item in value:
                key_name = item['key_name']
                encrypted_value = item['value']

                if not boxes.get(key_name):
                    try:
                        boxes[key_name] = init_secret_box(key_name=key_name)
                    except IOError as e:
                        logging.error(e)
                        continue  # Try next key
                try:
                    if six.PY2:
                        encrypted_value = encrypted_value.encode('ascii')
                        decrypted_value = boxes[key_name].decrypt(encrypted_value,
                                                                  encoder=encoding.URLSafeBase64Encoder)
                        decrypted_value = decrypted_value.decode('utf-8')
                    else:
                        encrypted_value = bytes(encrypted_value, 'ascii')
                        decrypted_value = boxes[key_name].decrypt(encrypted_value,
                                                                  encoder=encoding.URLSafeBase64Encoder).decode('utf-8')

                        config_dict[key[:-10]] = decrypted_value
                    del config_dict[key]
                    decrypted = True
                    break  # Decryption successful, do not try any more keys
                except exceptions.CryptoError as e:
                    logging.error(e)
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


def interpolate_list(config_dict, sub_list):
    """
    :param config_dict: Configuration dictionary
    :param sub_list: Sub configuration list

    :type config_dict: dict
    :type sub_list: list

    :return: Configuration list
    :rtype: list
    """
    for i in range(0, len(sub_list)):
        item = sub_list[i]
        # Substitute string items
        if isinstance(item, six.string_types) and '$' in item:
            template = Template(item)
            sub_list[i] = template.safe_substitute(config_dict)
        # Call interpolate_config with dict items
        if isinstance(item, dict):
            sub_list[i] = interpolate_config(config_dict, item)
        # Recursively call interpolate_list for list items
        if isinstance(item, list):
            sub_list[i] = interpolate_list(config_dict, item)
    return sub_list


def interpolate_config(config_dict, sub_dict=None):
    """
    :param config_dict: Configuration dictionary
    :param sub_dict: Sub configuration dictionary
    :type config_dict: dict
    :type sub_dict: dict

    :return: Configuration dictionary
    :rtype: dict
    """
    if not sub_dict:
        sub_dict = config_dict
    for key, value in sub_dict.items():
        # Substitute string values
        if isinstance(value, six.string_types) and '$' in value:
            template = Template(value)
            sub_dict[key] = template.safe_substitute(config_dict)

        # Check if lists contain string values, dicts or more lists
        # Offloaded to interpolate_list
        if isinstance(value, list):
            sub_dict[key] = interpolate_list(config_dict, value)

        # Recursively call interpolate_config for sub dicts
        if isinstance(value, dict):
            sub_dict[key] = interpolate_config(config_dict, value)
    return sub_dict
