import logging

from pydantic import BaseModel, Field, field_validator

from eduid.common.config.base import AuthnBearerTokenConfig, LoggingConfigMixin
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class AWSMixin(BaseModel):
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str | None = None


class ScimApiConfig(AuthnBearerTokenConfig, LoggingConfigMixin, AWSMixin):
    """
    Configuration for the SCIM API app
    """

    neo4j_uri: str = ""
    neo4j_config: dict = Field(default_factory=dict)
    signing_key_id: str
    login_enabled: bool = False
    no_authn_urls: list[str] = Field(default=["^/login/?$", "^/status/healthy$", "^/docs/?$", "^/openapi.json"])
    status_cache_seconds: int = 10
    # The expected value of the authn JWT claims['requested_access']['type']
    requested_access_type: str | None = "scim-api"
    # Invite config
    invite_url: str = ""
    invite_expire: int = 180 * 86400  # 180 days

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls, v: str) -> str:
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = removesuffix(v, "/")
        return v
