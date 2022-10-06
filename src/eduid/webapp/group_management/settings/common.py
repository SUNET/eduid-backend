# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
"""
Configuration (file) handling for the eduID group_management app.
"""

from typing import Any, Dict, Optional

from eduid.common.config.base import EduIDBaseAppConfig, MailConfigMixin


class GroupManagementConfig(EduIDBaseAppConfig, MailConfigMixin):
    """
    Configuration for the group_management app
    """

    app_name: str = "group_management"

    eduid_site_name: str = "eduID"
    eduid_site_url: str

    group_invite_template_html: str = "group_invite_email.html.jinja2"
    group_invite_template_txt: str = "group_invite_email.txt.jinja2"
    group_delete_invite_template_html: str = "group_delete_invite_email.html.jinja2"
    group_delete_invite_template_txt: str = "group_delete_invite_email.txt.jinja2"
    group_invite_url: str = "https://dashboard.eduid.se"
    mail_default_from: str = "no-reply@eduid.se"
    neo4j_config: Optional[Dict[str, Any]] = None
    neo4j_uri: str = ""
    scim_data_owner: str = "eduid.se"
    scim_external_id_scope: str = "eduid.se"
