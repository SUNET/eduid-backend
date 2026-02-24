from pydantic import Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, MagicCookieMixin
from eduid.webapp.ladok.client import LadokClientConfig

__author__ = "lundberg"


class LadokConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin):
    """
    Configuration for the ladok app
    """

    app_name: str = "eduid_ladok"
    ladok_client: LadokClientConfig
    dev_fake_users_in: list[str] = Field(default_factory=list)  # list of 'ladok_name's that allow linking in dev
