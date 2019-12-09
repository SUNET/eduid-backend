#
# Copyright (c) 2018 NORDUnet A/S
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

from abc import ABCMeta, abstractmethod
from flask import request

from eduid_webapp.actions.app import current_actions_app as current_app

from eduid_common.api.utils import get_static_url_for, urlappend
from eduid_userdb.actions.action import Action


class ActionError(Exception):
    """
    exception to be raised if the action to be performed fails.
    Instantiated with a message that informs about the reason for
    the failure.
    The message will be sent to the front end and should be
    translatable by it.
    
    The rm kwarg indicates to the actions app whether it should
    remove the action record from the db when encountering
    this exception.

    Example code, in the plugin::
    
      if test_some_condition(*args, **kwargs):
          follow_success_code_path(*args2, **kwargs2)
      else:
          msg = 'actionX.errorY'
          raise self.ActionError(msg, rm=boolean_value)
    
    Example code, in the actions app (obj is an action object,
    an instance of a class that extends ActionPlugin,
    defined in a plugin, and actions_db is an instance of
    eduid_userdb.actions.db.ActionsDB)::

      try:
          obj.perform_step(action)
      except obj.ActionError as exc:
          if exc.remove_action:
              actions_db.remove_action_by_id(action.action_id)
          failure_msg = exc.args[0]
          # return a 200 Ok with the failure_msg as the key 'message' in a dict

    :param msg: the reason for the failure
    :type msg: unicode
    :param rm: whether to remove the action from the db
               on catching the exception.
    :type rm: bool
    """

    def __init__(self, msg, rm=False):
        super(ActionError, self).__init__(msg)
        self.remove_action = rm


class ActionPlugin(object):
    """
    Abstract class to be extended by the different plugins for the
    actions app.
    
    ==DEPRECATED==
    ==============
    
    The derived classes in the plugins are set as the objects to which
    the entry point ``eduid_actions.action`` in those plugins point at.

    The packages for the plugins must have a name with the form
    ``eduid_action.<name>``, where <name> must coincide with the key in
    the entry point.
    For example, if we have a plugin ``eduid_action.tou``,
    that defines a class ``ToUPlugin`` (subclass of ``ActionPlugin``) in
    its ``__init__.py``, we would have as entry point in its ``setup.py``::
        
      entry_points='''
        [eduid_actions.action]
            tou = eduid_action.tou:ToUPlugin
      ''',
    
    //DEPRECATED==
    ==============
    
    The derived classes are placed in ``eduid_webapp.actions.actions``, in
    their own modules named with the appropriate action name.
    
    During the initialization of the actions app, if it receives a
    configuration parameter ``ACTIONS_PLUGINS`` containing the action name,
    the plugin will be registered and the app will be able to deal with the
    kind of actions managed by the plugin.
    """

    __metaclass__ = ABCMeta

    ActionError = ActionError

    PLUGIN_NAME = 'dummy'
    PACKAGE_NAME = 'eduid_webapp.actions.actions.' + PLUGIN_NAME

    class ValidationError(Exception):
        """
        exception to be raised if some form doesn't validate.
        Instantiated with a dict of field names to error messages.

        :param arg: error messages for each field
        :type arg: dict
        """

    @classmethod
    @abstractmethod
    def includeme(self, app):
        """
        Plugin specific configuration for the actions app.

        :param app: the flask app.
        :type app: flask.App
        """

    def get_number_of_steps(self):
        """
        The number of steps that the user has to take
        in order to complete this action.
        In other words, the number of requests the client will
        make to complete the action.

        :returns: the number of steps
        :rtype: int
        """
        return self.steps

    def get_url_for_bundle(self, action: Action) -> str:
        """
        Return the url for the bundle that contains the front-end javascript
        side of the plugin. To be injected into an index.html file.  If there
        is some error in the process, raise ActionError.

        :param action: the action as retrieved from the eduid_actions db
        :returns: the url
        :raise: ActionPlugin.ActionError
        """
        path = current_app.config.bundles_path
        version = current_app.config.bundles_version
        feature_cookie = request.cookies.get(current_app.config.bundles_feature_cookie)
        if feature_cookie and feature_cookie in current_app.config.bundles_feature_version:
            version = current_app.config.bundles_feature_version[feature_cookie]
        bundle_name = 'eduid_action.{}.js'
        env = current_app.config.environment
        if env == 'dev':
            bundle_name = 'eduid_action.{}-bundle.dev.js'
        elif env == 'staging':
            bundle_name = 'eduid_action.{}.staging.js'
        base = urlappend(path, bundle_name.format(self.PLUGIN_NAME))
        return get_static_url_for(base, version=version)

    @abstractmethod
    def get_config_for_bundle(self, action) -> dict:
        """
        Return any configuration parameters needed by the js bundle that
        contains the front-end javascript side of the plugin. If there
        is some error in the process, raise ActionError.

        :param action: the action as retrieved from the eduid_actions db
        :returns: the config parameters
        :raise: ActionPlugin.ActionError
        """

    @abstractmethod
    def perform_step(self, action: Action) -> dict:
        """
        The user has provided some data and needs feedback. The provided data
        should be in the request, and the action type and current step should
        be in the session. This may be the last step for this action,
        or an intermediate one. This method has the responsibility of updating
        or removing the action from the db.

        If there are no errors, we return any data we may need to send to the
        user, and raise ActionError otherwise.

        :param action: the action as retrieved from the eduid_actions db
        :raise: ActionPlugin.ActionError
        """
