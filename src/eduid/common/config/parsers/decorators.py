import logging
from collections.abc import Callable, Mapping
from functools import wraps
from string import Template
from typing import Any

from nacl import encoding, exceptions, secret

__author__ = "lundberg"

from eduid.common.config.parsers.exceptions import SecretKeyException


def decrypt(f: Callable):
    @wraps(f)
    def decrypt_decorator(*args, **kwargs):
        config_dict = f(*args, **kwargs)
        decrypted_config_dict = decrypt_config(config_dict)
        return decrypted_config_dict

    return decrypt_decorator


def read_secret_key(key_name: str) -> bytes:
    """
    :param key_name: Key file name
    :return: 32 bytes of secret data
    """
    sanitized_key_name = "".join([c for c in key_name if c.isalpha() or c.isdigit() or c == "_"])
    fp = f"/run/secrets/{sanitized_key_name}"
    with open(fp, "rb") as f:
        return encoding.URLSafeBase64Encoder.decode(f.readline())


def init_secret_box(key_name: str | None = None, secret_key: bytes | None = None) -> secret.SecretBox:
    """
    :param key_name: Key file name
    :param secret_key: 32 bytes of secret data
    :return: SecretBox
    """
    if not secret_key:
        if not key_name:
            raise SecretKeyException("Can not initialize a SecretBox without either key_name or secret_key")
        secret_key = read_secret_key(key_name)
    return secret.SecretBox(secret_key)


def decrypt_config(config_dict: Mapping[str, Any]) -> Mapping[str, Any]:
    """
    :param config_dict: Configuration dictionary
    :return: Configuration dictionary
    """
    boxes: dict = {}
    new_config_dict: dict = {}
    for key, value in config_dict.items():
        if key.lower().endswith("_encrypted"):
            decrypted = False
            for item in value:
                key_name = item["key_name"]
                encrypted_value = item["value"]

                if not boxes.get(key_name):
                    try:
                        boxes[key_name] = init_secret_box(key_name=key_name)
                    except OSError as e:
                        logging.error(e)
                        continue  # Try next key
                try:
                    encrypted_value = bytes(encrypted_value, "ascii")
                    decrypted_value = (
                        boxes[key_name].decrypt(encrypted_value, encoder=encoding.URLSafeBase64Encoder).decode("utf-8")
                    )
                    new_config_dict[key[:-10]] = decrypted_value
                    decrypted = True
                    break  # Decryption successful, do not try any more keys
                except exceptions.CryptoError as e:
                    logging.error(e)
                    continue  # Try next key
            if not decrypted:
                logging.error(f"Failed to decrypt {key}:{value}")
        else:
            new_config_dict[key] = value
    return new_config_dict


def interpolate(f: Callable):
    @wraps(f)
    def interpolation_decorator(*args, **kwargs):
        config_dict = f(*args, **kwargs)
        interpolated_config_dict = interpolate_config(config_dict)
        for key in list(interpolated_config_dict.keys()):
            if key.lower().startswith("var_"):
                del interpolated_config_dict[key]
        return interpolated_config_dict

    return interpolation_decorator


def interpolate_list(config_dict: dict[str, Any], sub_list: list) -> list:
    """
    :param config_dict: Configuration dictionary
    :param sub_list: Sub configuration list

    :return: Configuration list
    """
    for i in range(0, len(sub_list)):
        item = sub_list[i]
        # Substitute string items
        if isinstance(item, str) and "$" in item:
            template = Template(item)
            sub_list[i] = template.safe_substitute(config_dict)
        # Call interpolate_config with dict items
        if isinstance(item, dict):
            sub_list[i] = interpolate_config(config_dict, item)
        # Recursively call interpolate_list for list items
        if isinstance(item, list):
            sub_list[i] = interpolate_list(config_dict, item)
    return sub_list


def interpolate_config(config_dict: dict[str, Any], sub_dict: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    :param config_dict: Configuration dictionary
    :param sub_dict: Sub configuration dictionary

    :return: Configuration dictionary
    """
    if not sub_dict:
        sub_dict = config_dict
    # XXX case insensitive substitution - transitioning to lc config
    ci_config_dict = {}
    for k, v in config_dict.items():
        ci_config_dict[k] = v
        ci_config_dict[k.upper()] = v
    for key, value in sub_dict.items():
        # Substitute string values
        if isinstance(value, str) and "$" in value:
            template = Template(value)
            sub_dict[key] = template.safe_substitute(ci_config_dict)

        # Check if lists contain string values, dicts or more lists
        # Offloaded to interpolate_list
        if isinstance(value, list):
            sub_dict[key] = interpolate_list(ci_config_dict, value)

        # Recursively call interpolate_config for sub dicts
        if isinstance(value, dict):
            sub_dict[key] = interpolate_config(ci_config_dict, value)
    return sub_dict
