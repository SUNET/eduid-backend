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

from flask import Flask

from eduid_common.authn.utils import get_saml2_config
from eduid_common.api.app import eduid_init_app


def authn_init_app(name, config):
    """
    Create an instance of an authentication app.

    First, it will load the configuration from the file system, according to
    the logic in `eduid_common.config.parsers.INIConfigParser`, and update
    it with any settings given in the `config` param.
    
    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    and finally all needed blueprints will be registered with it.
    
    :param name: The name of the instance, it will affect the configuration file
                 loaded from the filesystem.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """
    from . import acs_actions
    app = eduid_init_app(name, config, app_class=Flask)
    app.saml2_config = get_saml2_config(app.config['SAML2_SETTINGS_MODULE'])
    app.config['SAML2_CONFIG'] = app.saml2_config

    from eduid_webapp.authn.views import authn_views
    app.register_blueprint(authn_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    app.logger.info('Init {} app...'.format(name))

    return app
