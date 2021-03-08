from eduid_common.config.base import AmConfigMixin, EduIDBaseAppConfig


class PersonalDataConfig(EduIDBaseAppConfig, AmConfigMixin):
    app_name: str = 'personal_data'
