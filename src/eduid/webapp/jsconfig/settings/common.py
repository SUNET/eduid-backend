from eduid.common.config.base import EduIDBaseAppConfig, PasswordConfigMixin, TouConfigMixin
from eduid.webapp.jsconfig.settings.jsapps import JsAppsConfig


class JSConfigConfig(EduIDBaseAppConfig, TouConfigMixin, PasswordConfigMixin):
    """
    Configuration for the jsconfig app
    """

    app_name: str = "jsconfig"
    mongo_uri: str = "mongo_uri_not_used_in_jsconfig"
    token_service_url: str = "token_service_not_used_in_jsconfig"
    jsapps: JsAppsConfig
    # backwards compatible fixes that should be removed
    fix_dashboard_uppercase_config: bool = True
    fix_dashboard_available_languages: bool = True
    fix_signup_uppercase_config: bool = True
    fix_signup_available_languages: bool = True
