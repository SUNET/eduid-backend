import os
import os.path
import ConfigParser


DEFAULT_CONFIG_FILE_NAME = 'eduid_lookup_mobile.ini'
DEFAULT_PASSWORD_FILE_NAME = 'eduid_lookup_mobile.pw'


def get_config_file(conf_file_name):
    """Get the configuration file looking for it in several places.

    The lookup order is:
    1. A file named acording to the value of the EDUID_IDPROOFING_MOBILE_CONFIG env variable
    2. A file named eduid_lookup_mobile.ini In the current working directory
    3. A file named .eduid_lookup_mobile.ini in the user's home directory
    4. A file named eduid_lookup_mobile.ini in the system configuration directory
    """
    file_name = os.path.join(os.environ.get('EDUID_IDPROOFING_MOBILE_CONFIG', '/'), conf_file_name)

    if os.path.exists(file_name):
        return file_name

    user_file = os.path.expanduser(
        os.path.join('~', '.', conf_file_name))
    if os.path.exists(user_file):
        return user_file

    global_file = os.path.join('/etc', conf_file_name)
    if os.path.exists(global_file):
        return global_file


def read_configuration():
    """Read the settings from environment or .ini file and return them as a dict"""
    settings = {}

    config = ConfigParser.RawConfigParser()

    # Add config
    config_file = get_config_file(DEFAULT_CONFIG_FILE_NAME)
    if config_file is not None:
        config.read(config_file)

        if config.has_section('main'):
            settings = dict([(s.upper(), v) for s, v in config.items('main')])

    # Add passwords
    config_file = get_config_file(DEFAULT_PASSWORD_FILE_NAME)
    if config_file is not None:
        config.read(config_file)

        if config.has_section('main'):
            for s, v in config.items('main'):
                settings[s.upper()] = v

    return settings