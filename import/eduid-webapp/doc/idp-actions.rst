eduID Actions application
+++++++++++++++++++++++++

The point of this application is to be able to interrupt the process
of issuing a SAML assertion by the 
`eduID IdP <https://github.com/SUNET/eduid-IdP>`_ and force the end user
to perform arbitrary actions before the IdP finally returns the response
to the SAML request. Examples of actions might be to sign a new version
of the terms o use, or force the user to change password.
The actions will be represented by documents in an actions collection
in an eduid_actions MongoDB database.
When there are pending actions for a user that has issued a request to the
IdP, the IdP will redirect the user to the actions app,
that will let the users perform the required actions, and, upon success,
redirect the user back to the IdP.

All the logic for each kind of action is provided by a plugin package,
that can declare a number of setuptools entry points that will be
described below.

Database
========

There is an ``eduid_actions`` MongoDB db with an ``actions`` collection
for the actions that need to be performed, with schema:

User (``eppn``: String, required)
   identifies the user that must perform an action

Action (``action``: String, required)
   identifies the type of action to be performed

Session (``session``: String, optional)
   An identifier of the client session requiring the action,
   for the cases when the same user opens sessions with different
   user agents simultaneously. This identifier is particular to the actions app
   and has nothing to do with either the session in the IdP or the webapps
   session.

Preference (``preference``: Int, required)
   A way to deterministically order the actions when a user has
   more than one pending action.

Params (``params``: Dict, possibly empty)
   An arbitrary dictionary of parameters specific for the action to be
   performed.

Example document::
  
   {'_id': ObjectId('234567890123456789012301'),
    'eppn': 'hubba-bubba',
    'action': 'accept_tou',
    'session': 'xyz',
    'preference': 100
    'params': {
        'version': '2014-v2'
        }
    }

General Process
===============

On the IdP, before the action
-----------------------------

As soon as a user is identified, the IdP checks whether the user needs to
perform any action, querying the eduid_actions db.

Examination of the SAML request can result in adding actions to the db.  These
actions may be specific for the particular request as well as for the user, so
the IdP may create a session identifier and add it to the document inserted in
the eduid_actions db.

If any action is needed for the user, the process of issuing a SAML assertion
is interrupted, and we redirect the user to the actions app, with a URL like::

   https://actions.eduid.se/

Some data will be passed to the actions app in the shared session to convince
the actions app that the IdP has already identified the user.

The needed action is performed - or not
---------------------------------------

If the actions app validates the request, it sends in the
response an index.html with a js script that again queries the actions app,
asking for the url of a react/redux bundled app to load, that will
lead the user through the process required to perform the needed action. The
actions app must then choose which of the pending actions has highest
precedence, and use that choice to load the appropriate plugin to, among other
things, produce the URL for the bundle.

Once the client receives the URL and uses it to load the bundled js app, it
will again query the actions app for any configuration needed for the action to
be performed. Again, the actions app uses the loaded plugin to provide it.

The js app will then lead the user through whatever steps are necessary,
calling the `perform-step` method in the actions backend whenever it needs
feedback from the server - or when all steps have been taken. The backend uses
the loaded plugin to provide the needed feedback.

The action may end in success, or not. It is responsibility of the plugins to
act upon the user's actions. If, for example, the user accepts the new terms of
service, the corresponding plugin should record in the eduid_consent db the new
acceptance of terms, and delete the entry in the eduid_actions db.
   
In the case where the action is not successfully performed, the user should be
notified and the general workflow should end here.

We may need to set a record somewhere that some actions have already been
performed for this user (appart from deleting the entry in the eduid_actions
db), for the cases when these actions have arisen from examination of the
SAML request, so that we do not enter a loop when we get back to the IdP.

Once some action is completed, the client app will query the backend for any
additional pending actions, and the process will be restarted for each of them.
Care must be taken for the case where there are actions pending for the user
but for a different session.

Checking that there are no more actions to be performed may require more than
querying the eduid_actions db, if some action stems from the particular SAML
request being processed. In some cases it may be necessary to query some other
db (e.g., the eduid_attributes_consent db).

Once all actions are successfully performed, the actions app will redirect the
user back to the IdP, to complete the authentication process and be sent to
whatever RP originally looked for.

Anatomy of the actions app(s) and plugins
=========================================

There are several sides that participate in this functionality.

1. When the IdP receives an authn request, it may add new actions to the db.

2. When the IdP receives an authn request, it may find that there are pending
   actions - and redirect the user to the actions app.

3. The actions app will provide the user with a client js app appropriate for
   the current pending action.

4. The actions app will respond adecuately to each action-specific request
   coming from the client app.

5. Once the action is completed, the actions app may want to update the central
   db with any action-specific attributes produced in the process.

To achieve this, each action plugin will need the following pieces:

1. A plugin for the IdP, capable of examining a SMAL2 authn request and adding
   new pending action to the db. Not all action plugins will need this.

2. A plugin for the actions backend app, that will be able to provide a URL
   pointing to the bundled client side app, configuration for it, and will be
   able to respond to whatever calls the client app needs to make.

3. A bundled client side app, that will provide the UI needed for each
   particular action and will call the backend app with whatever data it
   receives from the user.

4. A plugin for the attribute manager that will be able to gather all the data
   that the manager needs to store in the central db.

Each action will be defined in a plugin, which consists of 2 parts: a Python
package with name `eduid_action.<xxx>` that resides in the `eduid-action` repo,
whose code is accessed through setuptools entry points, and Javascript code
that resides in the `eduid-front` repo.

These plugins can define 4 different Python setuptools entry points:
one for adding new actions, another for acting upon a pending action, and
2 others for updating the central user db with any new data that may have
been collected when performing the action.

Code for the IdP
----------------

For adding new actions, the plugins must be installed in the python environment
where the IdP runs. The IdP must have a configuration setting named
`action_plugins` with a list of plugin names, and for each name, a module
`eduid_action.<plugin_name>.idp` must be present in the python path, with a
callable named `add_actions` that accepts as arguments an instance of an IdP
application (``eduid_idp.idp:IdPApplication``), a user object
(``eduid_userdb.user:User``), and an IdP ticket
(``eduid_idp.login.SSOLoginData``), and adds pending actions to the db.

For backwards compattibility, the callables to add new pending actions can also
be configured as entry points, named ``eduid_actions.add_actions``, and with
the same signature as the callables configured in the settings.

Care must be taken to only add plugin names to the `action_plugins` setting
when they cease to have setuptools entry points pointing to them, otherwise
they will be executed twice, and redundant actions will be added to the db.

Code for the actions backend app
--------------------------------

For acting upon a pending action, the plugin must be installed in the python
environment where the actions Flask app runs. It must declare an entry point
named ``eduid_actions.action``, pointing to a python class with a number of
methods. The API of the objects returned by the plugins is described in the
``eduid_webapp.actions.action_abc:ActionPlugin`` abstract base class.

Code for the attribute manager
------------------------------

If an action has recorded some information that needs to end up in the central
user db, the plugin may act as an AM plugin. For this, it must be installed in
the python environment where the AM app runs. The AM must have a configuration
setting named ``ACTION_PLUGINS`` with a list of plugin names, and for each
configured plugin name the python path must include a module at
``eduid_action.<plugin_name>.am``, containing 2 callables: ``plugin_init`` and
``attribute_fetcher`. The ``plugin_init`` callable must accept a dictionary
with am configuration data, and return an object that has attributes needed by
the attribute fetcher. The ``attribute_fetcher`` callable must accept as
arguments the object provided by the first entry point and an user id
(``bson.ObjectId``), and return a dictionary ready to use by pymongo to update
the user object with the provided id in the central user db.  More details
about AM plugins in the eduid-am package.

Alternatively, for backwards compatibility, the callables referred to in the
previous paragraph may be referred to by setuptools entry points:
``eduid_am.plugin_init`` and ``eduid_am.attribute_fetcher``. If this is the
case, the plugin name should not be present in the ``ACTION_PLUGINS`` setting,
otherwise users may end up with duplicated information.

Javascript code
---------------

The Javascript code that governs the specific workflow for each particular
action is located on the eduid-front repo, under a directory
`plugins/<plugin-name>/`.

The bundle for each plugin will have a name like the package that contains it
(e.g., `eduid_action.tou.js`), and all will be served from the same base URL.
To build the bundles for the plugins, there is a special npm script::

  $ npm run manage:plugins

There are several facilities in eduid-front to help develop the client side for
the different plugins. There is a bare skeleton to be used as a starting point
for developing the plugins, that import these facilities in the proper places,
and which is located in `eduid-front/plugin-skel/`.

Testing
=======

The Python tests may use a test case defined in
`eduid_webapp.actions.testing.ActionsTestCase`. Tests developed with this
facility may be run in a virtualenv where eduid_webapp and its dependencies
have been installed.

The Javascript tests may be developed as usual, and they may be executed
together with all the rest of tests in eduid-front::

  $ npm run test-headless


Examples of actions
===================

a. ToU - The user has to accept a new version of the terms of use.

b. 2FA - user is trying to log in to some resource demanding additional
   information. The IdP only did password authentication, and wants the
   action_app to do some additional authentication (could be hardware token or
   SMS code for example). Maybe there would be a separate plugin per
   authentication type .

c. CAPTCHA - not sure one wants to captcha after verifying the password was
   right, but perhaps... we should just keep the possibility in mind when
   designing this.

d. Announcements for downtime, new features or whatever.

e. Attribute release consent (per SP or even per login). This one might add a
   requirement to be able to communicate richer results to the IdP than just True
   or False. If the result is to be stored per SP the result of the action plugin
   would probably be stored in MongoDB somewhere, but maybe there will be a need
   to add URI parameters with return value to the URL used to return the user to
   the IdP? This plugin will be important.

f. Password change - we will require users to change password every X years.

Configuration
=============

The configuration parameters needed for the backend actions app are:

IDP_URL
    The URL of the IdP, where the app will redirect the user once there are no
    more pending actions

BUNDLES_PATH
    The path from which js bundles are served on the static files server.

There is an `actions` section in the configuration for etcd that can hold these
settings, and any additional setting needed by any particular action plugin.
