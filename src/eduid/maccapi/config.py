import logging
from pathlib import Path
from typing import Optional

from pydantic import Field, validator

from eduid.common.config.base import AuthnBearerTokenConfig, LoggingConfigMixin
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class MAccApiConfig(AuthnBearerTokenConfig, LoggingConfigMixin):
    """
    Configuration for the Managed Accounts API app
    """

    vccs_url: str = "http://vccs:8080/"
    # The expected value of the authn JWT claims['requested_access']['type']
    requested_access_type: Optional[str] = "maccapi"

    @validator("application_root")
    def application_root_must_not_end_with_slash(cls, v: str):
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = removesuffix(v, "/")
        return v
