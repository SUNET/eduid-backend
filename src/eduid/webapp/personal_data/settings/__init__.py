from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, FrontendActionMixin


class PersonalDataConfig(EduIDBaseAppConfig, AmConfigMixin, FrontendActionMixin):
    app_name: str = "personal_data"
