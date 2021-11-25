# -*- coding: utf-8 -*-

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig
from eduid.webapp.ladok.eduid_ladok_client import LadokClientConfig

__author__ = 'lundberg'


class LadokConfig(EduIDBaseAppConfig, AmConfigMixin):
    """
    Configuration for the ladok app
    """

    app_name: str = 'ladok'
    ladok_client: LadokClientConfig
