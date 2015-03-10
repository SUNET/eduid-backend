import os
import os.path
import ConfigParser


DEFAULT_CONFIG_FILE_NAME = 'eduid_lookup_mobile.ini'
DEFAULT_PASSWORD_FILE_NAME = 'eduid_lookup_mobile.pw'


def get_config_file(file_name):
    """Get the configuration file looking for it in several places.

    The lookup order is:
    1. In the current working directory
    2. in the user's home directory
    3. in the system configuration directory /etc
    """
    if os.path.exists(file_name):
        return file_name

    user_file = os.path.expanduser(
        os.path.join('~', '.', file_name))
    if os.path.exists(user_file):
        return user_file

    global_file = os.path.join('/etc', file_name)
    if os.path.exists(global_file):
        return global_file

    test_file = os.path.join('./', conf_file_name)
    if os.path.exists(test_file):
        return test_file


def read_configuration():
    """Read the settings from environment or .ini file and return them as a dict"""
    settings = {}
    # Add config and passwords optionally from second config file
    cfg_fn = os.environ.get('EDUID_IDPROOFING_MOBILE_CONFIG', DEFAULT_CONFIG_FILE_NAME)
    for fn in [cfg_fn, DEFAULT_PASSWORD_FILE_NAME]:
        config_file = get_config_file(fn)
        if config_file is not None:
            config = ConfigParser.RawConfigParser()
            config.read(config_file)

            if config.has_section('main'):
                for s, v in config.items('main'):
                    settings[s.upper()] = v

    return settings