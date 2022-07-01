# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Mapping

from pydantic import AnyUrl, BaseModel, Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig

__author__ = 'lundberg'


class SvipeIdConfig(EduIDBaseAppConfig, AmConfigMixin):
    """
    Configuration for the svipe_id app
    """

    app_name: str = "svipe_id"
    client_registration_info: Dict[str, str] = Field(default={'client_id': '', 'client_secret': ''})
    provider_configuration_info: Dict[str, str] = Field(
        default={
            'issuer': '',
        }
    )
    proofing_redirect_url: str
