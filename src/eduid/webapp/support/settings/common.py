#


from pydantic import Field

from eduid.common.config.base import EduIDBaseAppConfig


class SupportConfig(EduIDBaseAppConfig):
    """
    Configuration for the support app
    """

    token_service_url_logout: str
    eduid_static_url: str

    app_name = "support"

    support_personnel: list[str] = Field(default=[])
