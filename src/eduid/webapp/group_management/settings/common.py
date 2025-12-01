"""
Configuration (file) handling for the eduID group_management app.
"""

from typing import Any

from eduid.common.config.base import EduIDBaseAppConfig


class GroupManagementConfig(EduIDBaseAppConfig):
    """
    Configuration for the group_management app
    """

    app_name: str = "group_management"

    # Email settings (no longer using MailRelay/Celery)
    eduid_site_name: str = "eduID"
    eduid_site_url: str = "https://eduid.se"
    group_invite_url: str = "https://dashboard.eduid.se"
    neo4j_config: dict[str, Any] | None = None
    neo4j_uri: str = ""
    scim_data_owner: str = "eduid.se"
    scim_external_id_scope: str = "eduid.se"
