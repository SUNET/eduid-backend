#
# Copyright (c) 2013-2016 NORDUnet A/S
# Copyright (c) 2019 SUNET
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

from typing import Optional

from pydantic import Field

from eduid.common.config.base import WorkerConfig


class AmConfig(WorkerConfig):
    """
    Configuration for the attribute manager celery worker
    """

    new_user_date: str = '2001-01-01'
    action_plugins: list = Field(default_factory=lambda: ['tou'])


class MsgConfig(WorkerConfig):
    """
    Configuration for the msg celery worker
    """

    audit: bool = True
    devel_mode: bool = False
    mail_certfile: str = ''
    mail_host: str = 'localhost'
    mail_keyfile: str = ''
    mail_password: str = ''
    mail_port: int = 25
    mail_starttls: bool = False
    mail_username: str = ''
    mongo_dbname: str = 'eduid_msg'
    navet_api_pw: str = ''
    navet_api_uri: str = ''
    navet_api_user: str = ''
    navet_api_verify_ssl: bool = False
    sms_acc: str = ''
    sms_key: str = ''
    sms_sender: str = 'eduID'
    template_dir: str = ''


class MobConfig(WorkerConfig):
    """
    Configuration for the lookup mobile celery worker
    """

    devel_mode: bool = False
    log_path: str = ''
    teleadress_client_password: str = ''
    teleadress_client_user: str = ''
