from eduid.common.config.base import EduIDBaseAppConfig, PasswordConfigMixin, TouConfigMixin
from eduid.webapp.jsconfig.settings.jsapps import JsAppsConfig


class JSConfigConfig(EduIDBaseAppConfig, TouConfigMixin, PasswordConfigMixin):
    """
    Configuration for the jsconfig app
    """

    app_name: str = "jsconfig"
    mongo_uri: str = "mongo_uri_not_used_in_jsconfig"
    jsapps: JsAppsConfig
