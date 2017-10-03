# -*- coding: utf-8 -*-
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

from __future__ import absolute_import

from flask_babel import Babel

from eduid_common.api.app import eduid_init_app
from eduid_common.api import mail_relay
from eduid_common.api import am
from eduid_userdb.proofing import EmailProofingUserDB
from eduid_userdb.proofing import EmailProofingStateDB


def email_init_app(name, config):
    """
    Create an instance of an eduid email app.

    First, it will load the configuration from email.settings.common
    then any settings given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    all needed blueprints will be registered with it,
    and finally the app is configured with the necessary db connections.

    :param name: The name of the instance, it will affect the configuration loaded.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config)
    app.config.update(config)

    from eduid_webapp.email.views import email_views
    app.register_blueprint(email_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    app = am.init_relay(app, 'eduid_email')
    app = mail_relay.init_relay(app)

    app.private_userdb = EmailProofingUserDB(app.config['MONGO_URI'])
    app.proofing_statedb = EmailProofingStateDB(app.config['MONGO_URI'])

    app.logger.info('Init {} app...'.format(name))

    babel = Babel(app)
    app.babel = babel

    return app
