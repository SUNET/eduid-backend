import os
import os.path
import ConfigParser


DEFAULT_CONFIG_FILE_NAME = 'eduid_msg.ini'


def get_config_file():
    """Get the configuration file looking for it in several places.

    The lookup order is:
    1. A file named acording to the value of the EDUIM_MSG_CONFIG env variable
    2. A file named eduid_msg.ini In the current working directory
    3. A file named .eduim_msg.ini in the user's home directory
    4. A file named eduim_msg.ini in the system configuration directory
    """
    file_name = os.environ.get('EDUID_MSG_CONFIG', DEFAULT_CONFIG_FILE_NAME)

    if os.path.exists(file_name):
        return file_name

    user_file = os.path.expanduser(
        os.path.join('~', '.', DEFAULT_CONFIG_FILE_NAME))
    if os.path.exists(user_file):
        return user_file

    global_file = os.path.join('/etc', DEFAULT_CONFIG_FILE_NAME)
    if os.path.exists(global_file):
        return global_file


def read_setting_from_env(settings, key, default=None):
    env_variable = key.upper()
    if env_variable in os.environ:
        return os.environ[env_variable]
    else:
        return settings.get(key, default)


def read_list(settings, prop, default=[]):
    raw = read_setting_from_env(settings, prop, None)
    if raw is None or raw.strip() == '':
        return default

    return [e for e in raw.split('\n') if e is not None and e.strip() != '']


CONFIG_VAR_TYPES = {
    # <var name>.lower(): (<read function>, <default>),
    'celery_accept_content': (read_list, ['application/json']),
}


def read_configuration():
    """
    Read the settings from environment or .ini file and return them as a dict

    The values are decoded as JSON, or used as-is if they can't be decoded as JSON.
    """
    settings = {}

    config_file = get_config_file()
    if config_file is not None:
        config = ConfigParser.RawConfigParser()
        config.read(config_file)

        if config.has_section('main'):
            for key, val in config.items('main'):
                if key in CONFIG_VAR_TYPES:
                    func, default = CONFIG_VAR_TYPES[key]
                else:
                    func = read_setting_from_env
                    default = ''
                settings[key.upper()] = func({key: val}, key, default=default)

    return settings
