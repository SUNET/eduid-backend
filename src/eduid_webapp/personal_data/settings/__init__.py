from eduid_common.config.base import CeleryConfigMixin, EduIDBaseAppConfig


class PersonalDataConfig(EduIDBaseAppConfig, CeleryConfigMixin):
    app_name: str = 'personal_data'
