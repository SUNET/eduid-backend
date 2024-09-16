"""
Configuration (file) handling for the eduID group_management app.
"""

from typing import Any

from eduid.common.config.base import EduIDBaseAppConfig, MailConfigMixin


class GroupManagementConfig(EduIDBaseAppConfig, MailConfigMixin):
    """
    Configuration for the group_management app
    """

    app_name: str = "group_management"

    group_invite_template_html: str = "group_invite_email.html.jinja2"
    group_invite_template_txt: str = "group_invite_email.txt.jinja2"
    group_delete_invite_template_html: str = "group_delete_invite_email.html.jinja2"
    group_delete_invite_template_txt: str = "group_delete_invite_email.txt.jinja2"
    group_invite_url: str = "https://dashboard.eduid.se"
    mail_default_from: str = "no-reply@eduid.se"
    neo4j_config: dict[str, Any] | None = None
    neo4j_uri: str = ""
    scim_data_owner: str = "eduid.se"
    scim_external_id_scope: str = "eduid.se"
