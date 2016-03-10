#
# Copyright (c) 2016 NORDUnet A/S
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

from eduid_common.config.parsers import IniConfigParser


class APIConfigParser(IniConfigParser):
    """
    """
    def __init__(self, config_file_name, config_environment_variable=None):
        super(APIConfigParser, self).__init__(config_file_name,
                                              config_environment_variable)
        self.known_special_keys.update({
            'debug': (self.read_setting_from_env_bool, False),
            'testing': (self.read_setting_from_env_bool, False),
            'session_cookie_httponly': (self.read_setting_from_env_bool, False),
            'session_cookie_secure': (self.read_setting_from_env_bool, False),
            'permanent_session_lifetime': (self.read_setting_from_env_int, 3600),
            'use_x_senfile': (self.read_setting_from_env_bool, False),
            'propagate_exceptions': (self.read_setting_from_env_bool, False),
            'preserve_context_on_exception': (self.read_setting_from_env_bool, False),
            'max_content_length': (self.read_setting_from_env_int, 0),
            'send_file_max_age_default': (self.read_setting_from_env_int, 43200),
            'trap_http_exceptions': (self.read_setting_from_env_bool, False),
            'trap_bad_request_errors': (self.read_setting_from_env_bool, False),
            'json_as_ascii': (self.read_setting_from_env_bool, False),
            'json_sort_keys': (self.read_setting_from_env_bool, True),
            'jsonify_prettyprint_regular': (self.read_setting_from_env_bool, True),
            'redis_port': (self.read_setting_from_env_int, 6379),
            'redis_db': (self.read_setting_from_env_int, 0),
            })

