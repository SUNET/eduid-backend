import os
import os.path
import ConfigParser


DEFAULT_CONFIG_FILE_NAME = 'eduid_am.ini'


def get_config_file():
    """Get the configuration file looking for it in several places.

    The lookup order is:
    1. A file named acording to the value of the EDUIM_AM_CONFIG env variable
    2. A file named eduid_am.ini In the current working directory
    3. A file named .eduim_am.ini in the user's home directory
    4. A file named eduim_am.ini in the system configuration directory
    """
    file_name = os.environ.get('EDUID_AM_CONFIG', DEFAULT_CONFIG_FILE_NAME)

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


def read_mapping(settings, prop, available_keys=None, default=None, required=True):
    raw = read_setting_from_env(settings, prop, '')

    if raw.strip() == '':
        return default

    rows = raw.strip('\n ').split('\n')

    mapping = {}

    for row in rows:
        splitted_row = row.split('=')
        key = splitted_row[0].strip()
        if len(splitted_row) > 1:
            value = splitted_row[1].strip()
        else:
            value = ''
        if available_keys is None or key in available_keys:
            mapping[key] = value

    if available_keys is not None:
        if (len(mapping.keys()) != len(available_keys) and
                not 'testing' in settings):
            return None

    return mapping


def read_list(settings, prop, default=[]):
    raw = read_setting_from_env(settings, prop, None)
    if raw is None or raw.strip() == '':
        return default

    return [e for e in raw.split('\n') if e is not None and e.strip() != '']


def read_configuration():
    """
    Read the settings from environment or .ini file and return them as a dict
    """
    settings = {}

    config = ConfigParser.RawConfigParser()

    config_file = get_config_file()
    if config_file is not None:
        config.read(config_file)

        if config.has_section('main'):
            settings = dict([(s.upper(), v) for s, v in config.items('main')])

    return settings
