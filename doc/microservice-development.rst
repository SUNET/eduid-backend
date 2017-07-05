
Development of eduID
====================

The eduID service is based on a collection of RESTish microservices that are
used by js front-end applications.

Development of microservices
----------------------------

EduID microservices are based on `Flask <http://flask.pocoo.org/>`_, and reside
in `github <https://github.com/SUNET/eduid-webapp/>`_, as Python packages
below ``src/eduid_webapp/``.

The main modules that comprise an eduID microservice are as follows.

views.py
........

This module holds the views for the app. A flask Blueprint is instantiated in
this module, and the views are registered in this blueprint.

app.py
......

In this module there must be a function that takes as parameters a str name
for the app and a dict of settings, and returns a Flask application.

The settings param is there to be able to inject test settings in tests,
and is not used for production.

The initial eduID app is obtained in this module by the use of the
``init_eduid_app`` function from ``eduid_common.api.app``. This function returns
a Flask app with the following special properties:

Skeleton generation
...................

A shortcut for creating the file structure and some boiler plate code is to use cookiecutter::

  pip install cookiecutter
  cd eduid-webapp/src/eduid_webapp
  cookiecutter ../../cookiecutter-app
  author [Your name]: lundberg
  directory_name [Snake case package name/app name, ex mobile_proofing]: mobile_proofing
  class_name [Camel case class name, ex MobileProofing]: MobileProofing

**Authentication**

For any request, the app checks that it carries an authn token as a cookie,
and if not, redirects to the authentication service. Thhe logic for this is
implemented in ``eduid_common.authn.middleware``.

**Configuration**

The app has an attribute ``config`` with all the configuration paramenters. These
parameters can be provided in several ways: in an ini file, in an etcd server,
and as mentioned above, as a dictionary when instantiating the app. The logic
for this is implemented in ``eduid-common.config.parsers``.

Defaults for the configuration parameters common to all apps are kept in
``eduid_webapp.settings.common``. Overrides of these settings for specific apps,
and defaults for settings  that are specific for each app, are kept in a Python
module (for each app), at ``eduid_webapp.<some_app>.settings.common``. And
the changes to these default settings particular to a deployment of the app,
are kept in etcd, in `eduid-developer/etcd/conf.yaml`.

When new settings are added to etcd, we must run a script to load them::

  $ cd eduid-developer/etcd
  $ python etcd_config_bootstrap.py -v --host etcd.eduid.docker

**Logging**

The app has a ``logger`` attribute that we can use to send information to
the logs.

**Database**

The app has a connection to the central user db in the attribute
``central_userdb``. This db is only used to read user data; to write user data
we must use dbs specific for each app, that sinchronize with the central db
through celery tasks. This attribute points to an instance of
``eduid_userdb.UserDB``, that provides methods to save data to and retrieve
data from the db, in the form of ``eduid_userdb.User`` objects.

On top of all this, each app can initialize its flask app with whatever covers
the specific needs of the particular microservice. The most common tasks are
registering the blueprint(s) instantiated in the ``views.py`` module, and
providing connections for the local dbs needed by the microservice, in the form
of proxies developed in ``eduid_userdb``.

All manipulation of persistent data is made through the objects and db proxies
developed in eduid_userdb.

run.py
......

Instantiate the app with the init function in ``app.py`` and run it.

schemas.py, validators.py
.........................

For input validation and deserialization of form submissions from users we
use `marsmallow <http://marshmallow.readthedocs.io/en/latest/index.html>`_.
Schemas are kept in schemas.py and validators in validators.py (surprise).

This is not to be  confused with input sanitation, that is performed
transparently for any access to request data, and is implemented in
``eduid_common.api.request``.

Testing microservices
.....................

**MongoTestCase**

There is a test case defined in ``eduid_userdb.testing.MongoTestCase`` that
provides a connection to a temporary mongodb instance, and an interface to it
in a ``amdb`` attribute that points to an instance of ``eduid_userdb.UserDB``.
This db comes preloaded with a couple of mock users defined in
``eduid_userdb.testing``.

**EduidAPITestCase**

There is a test case in ``eduid_common.api.testing.EduidAPITestCase``. This test
case has temporary instances of redis (for sessions) and of mongodb, and an
``app`` attribute pointing to an instance of a flask app.

Test cases extending this must implement an ``load_app(self, config)`` method
where they return the particular flask app to be tested, and can implement a
method ``update_config(self, config)`` where they can provide any needed
configuration params.

Sessions
........

The flask app returned by ``init_eduid_app`` has a custom session factory,
based on redis, implemented in ``eduid_common.session.session``, and adapted for
flask in ``eduid_common.api.session``. These sessions can be accesed as usual
in flask apps (in the ``session`` attribute of the app) and are shared by all
microservices, with the data kept in a central redis service.

Each request must carry a cookie with an authentication token, which is an
encrypted key for the session data in redis. If it doesn't, the request is
redirected to the authn service. If it does, the app retrieves the session
data from redis and holds it in ``session``.

In the session there is a key ``user_eppn`` with the eppn of the logged in user.
If we need the logged in user in some view, we use the ``require_dashboard_user``
decorator from ``eduid_common.api.decorators``, that provides a ``user`` argument
to the decorated view.

Creating a new microservice
...........................

We'll use the creation of a service to provide the js front-end apps with
configuration parameters, which we'll call `jsconfig`.

**Docker image**

In eduid-dockerfiles, create a new directory with a Dockerfile and a `start.sh`
script. The Dockerfile is in principle identical as in other services, e.g.
`personal-data`, and the `start.sh` script, which is just in charge of running
gunicorn, is also almost identical to that of other services, needing to change
just a couple of places where the name of the service appears.

**Docker environment**

The docker environment is created with docker-compose, and is configured in
`eduid-developer`. To add a new container based on the Dockerfile created above,
we need to add a new entry in `eduid/compose.yml`. Just copy the entry for
another ms, such as personal data, and change the image, the hostname, and the
ipv4_address (add a new one).

We also need a new directory in `eduid-developer`, named `eduid-jsconfig/`,
that will hold the exposed logs, configuration, and pid file.

Also, we need to add the new service to the DNS, in the script
`eduid-developer/start.sh`.

**Flask app**

Let's now develop the flask app that will be in charge of the service. First
we create a new subpackage in `eduid-webapp/src/eduid_webapp/`, which we call
`jsconfig`, and add an `__init__.py` file.

Then create a `settings` subpackage within the one created in the previous
paragraph, and within it, a `common.py` module with all settings needed
for the app. This module will hold the default settings. To change these
settings, we have to tell the etcd config server, adding the settings in
the `eduid-developer/eduid/conf.yml`.

Then create a `views.py` module with a flask blueprint and views.

Then we create an `app.py` module where we configure the application with all
the utilities it may need: database connections, etc. We can copy the `app`
module from an existing service and adapt it, for example `personal_data`.
Also the blueprint developed in `views.py` is registered here.

Finally, we create a `run.py` module that will run the app. This file is
referenced in the `start.sh` script we added to the docker image, as the wsgi
script to be run by gunicorn.

**Serve from nginx**

Configure nginx to act as reverse proxy for the service, adding a `location`
entry in `eduid-developer/eduid-html/etc/html.conf`.

**Starting the service**

The first time we run the service we need to create the docker image::

  $ cd eduid-dockerfiles/eduid-jsconfig
  $ docker build -t docker.sunet.se/eduid/eduid-jsconfig .

Then we start the whole environment::

  $ cd eduid-developer
  $ ./start.sh

Or just the new service::

  $ docker-compose -f eduid/compose.yml start jsconfig


Development of front end applications
-------------------------------------

Basic development stack
.......................

Front end apps are developed with `React <https://facebook.github.io/react/>`_,
and reside in `eduid-html/react`.

The development environment has a few pieces:

* `npm <https://www.npmjs.com/>`_.
  Node package manager, to manage dependencies and metadata. Configured
  in `react/package.json
  <https://github.com/SUNET/eduid-html/blob/master/react/package.json>`_. npm
  is also the main entry point to managing the
  dev environment, and defines the following scripts:

  * ``npm install [--save-dev <some-js-package>]`` installs the required
    package, or all dependencies if no package is specified.
  * ``npm start`` builds the bundle for development, starts a development
    http server, and watches the files for changes to rebundle and re-serve
    them.
  * ``npm test`` runs the tests.
  * ``npm run build`` makes a bundle for production use. This bundle is kept
    under version control, at least until the build process is integrated
    in puppet.

* `webpack <https://webpack.js.org/>`_.
  Webpack is a module bundler, whose main purpose is to bundle JavaScript
  files for usage in a browser. There are 2 config files for webpack, one
  `react/webpack.config.js
  <https://github.com/SUNET/eduid-html/blob/master/react/webpack.config.js>`_ for development and testing, and another
  `react/webpack.prod.config.js
  <https://github.com/SUNET/eduid-html/blob/master/react/webpack.prod.config.js>`_ for production bundles.

* `babel <https://babeljs.io/>`_.
  Babel is a transpiler, used by webpack to transpile react and es6 sources
  into the es5 bundles that can be interpreted by any browser. Configuration
  for babel is under the ``babel`` key in ``package.json``.

* `karma <https://karma-runner.github.io/1.0/index.html>`_.
  Karma is a test runner, configured in `react/karma.conf.js
  <https://github.com/SUNET/eduid-html/blob/master/react/karma.conf.js>`_. It is
  configured to use webpack to prepare the sources for the tests, `mocha
  <http://mochajs.org/>`_ as a
  real browser driver (to run the tests in firefox, chrome, etc.), and
  istambul/isparta for code coverage. The tests are written using `enzyme
  <https://medium.com/airbnb-engineering/enzyme-javascript-testing-utilities-for-react-a417e5e5090f>_, a
  testing framework for react. The tests  are kept in ``react/src/tests``, and
  must have a filename ending in ``-test.js``. There is a file
  ``react/src/test.webpack.js`` that acts as entry point for all tests for the
  runner.

React Components
................

We use react to build components, and redux to manage state and provide it to
said components. The state is kept in a central store managed by redux. The
basic idea is that there is a single one way flux of information: Events and
user interactions provoke changes in the central store, and from the store they
are passed to the components, that, when needed, are re-rendered, modifying the
UI. So, a particular state of the store determines a particular state of the
UI, and any change in the UI should be known by the store.

Components have properties (`props`), as the data that determines their own state
and behaviour. The value of those properties has 2 possible origins.  First,
when they are used as subcomponents of other components, these properties can
be provided as XML attributes in JSX. Second, the components are connected by
redux to the central store, so that when the central state changes, this change
can be transmitted to the components via their properties.

We store the components in `react/components`, where we basically define their
visual structure of subcomponents. The most basic components are bootstrap 3
components, provided by `react-bootstrap
<https://react-bootstrap.github.io/>`_.

The components are extended in `react/containers` with methods and event
handlers. It is in these container modules that redux connects the components
with the central state. This connection happens in 2 ways. First, methods
defned here have access to the central store, both to read from it, and to
modify it (see dispatching actions in the next paragraph). And, second, here
you define a map from the central state to the props of the component, so that
when the central state changes, the properties are updated and the components
rerendered.

To modify the central store, we define actions and dispatch them. Actions are
simple JSON objects that contain the information needed for atomic
modifications of the state. We also call actions to the functions that produce
those objects, kept in `react/actions`. These actions are provided to a
`dispatch` function from redux, and end up reaching specially defined `reducer`
functions, that reside in `react/reducers`. These reducers that examine the
actions and return a modified state.

For asynchronous actions, when some event requires sending requests over the
network, or long computations, we use `redux-saga
<https://www.npmjs.com/package/redux-saga>`_. Sagas are generator functions,
whose execution can be suspended while waiting for a yield statement. They can
also access the state in the central store, and dispatch actions. Each saga is
configured with a corresponding action, and what redux-saga basically does is
to watch the store for those actions, and, when they are dispatched to the
store, trigger the corresponding saga. This saga can then do its things
asynchronously without freezing the UI, and dispatch actions to notify of the
results of its operations.

Information flux
................

So, the normal flux of information, is a user triggers some event in the UI,
would be:

* The user triggers some event, e.g. by clicking some button;
* The event has a handler, that we have defined in the container corresponding
  to the component where the target of the event is, and assigned to the
  particular element via a ``onClick`` property (props);
* The handler can dispatch actions, and does dispatch one;
* the action is examined by redux-saga and if there is a saga configured for
  that action, it is executed - asynchronously.
* The action is passed to the reducers, that check its keys and modifies the
  state in the store;
* The modified state is passed to the "connected" containers that execute their
  ``mapStateToProps`` function, so transmitting the state to the props of the
  components.

Getting started
...............

To get started developing js components, first is having the code::

  $ git clone git@github.com:SUNET/eduid-html.git

Download the build environment::

  $ docker pull docker.sunet.se/eduid/debian-react:latest

Then we go to the react dir, and install all dependencies::

  $ cd eduid-html/react
  $ docker run --volume $PWD:/root/react -it docker.sunet.se/eduid/debian-react:latest
  $ npm install

We can now build the development bundle, or the production bundle. The
development bundle build procedure is continuous, the process stays on the
foreground monitoring changes in the code and rebuilding::

  $ npm run build  # production build
  $ npm start  # development build

The available `npm` commands can be seen in the `scripts` section of the
`package.json` file.

App initialization
..................

All code necessary for running the app is served in a single bundle. The
bundles that are built are specified in ``react/webpack.config.js``. For the
moment, while migrating to react apps, the bundle that is loaded is configured
in `the ini file for the dashboard
<https://github.com/SUNET/eduid-developer/blob/master/eduid-dashboard/etc/eduid-dashboard.ini#L161>`_.

The entry point that drives the bundle we are using (while migrating) comes for
the old dashboard js, and it still does its old thing, except that it also
loads the configured react components and renders them in the DOM. The function
that does this is ``init_app``, defined in the `init-app module
<https://github.com/SUNET/eduid-html/blob/master/react/src/init-app.js>`_, that
uses the store defined in the `store module
<https://github.com/SUNET/eduid-html/blob/master/react/src/store.js>`_.

Testing and debugging
.....................

We can also run the tests. We can simply run them and see the test coverage,
doing like this in the `react/` dir::

  $ npm test

If you want to debug the tests, you can insert a breackpoint in the js code
with `debugger;`. Then you have to run::

  $ npm run debug

You will have then a browser's window open, with a DEBUG button on the upper
right corner; click on it, and you will get a new tab in the browser. Open
the  inspector/developer tools in this new tab, reload the page, and the tests
will be run until it hits a `debugger` where it will stop execution.

It helps debugging to install the `react developer tools
<https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi>`_
and the `redux developer tools
<https://chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd>_.

i18n
....

For the internalization of the react apps we use react-intl and
babel-plugin-react-intl, that hooks message extraction with the webpack build
process. The messages are stored in ``react/i18n``, and the translations
are stored in ``react/i18n/l10n/<lang>.js``. Unfortunately this framework does not
follow the gettext standard, and thus cannot be used with transifex.

An example of an internationalized formatted message::

            <FormattedMessage
                    id="greeting.welcome_message"
                    defaultMessage={``
                        Welcome {name}, you have received {unreadCount, plural,
                            =0 {no new messages}
                            one {{formattedUnreadCount} new message}
                            other {{formattedUnreadCount} new messages}
                        }.
                    ``}
                    values={{
                        name: <b>uno</b>,
                        unreadCount: 2,
                        formattedUnreadCount: (
                            <b><FormattedNumber value={2} /></b>
                        ),
                    }}
            />


Messages are defined in the ``i18n-messages.js`` module, and are then used in
the components through the ``props.l10n('msg.id')`` fuction.


css
...

Custom css is managed with sass and webpack. There is a ``src/variables.scss``
file to hold common settings. To add style to some component, we have to add an
scss file to ``src/components/, import from it the ``variables.scss`` file,
and then import in our js(x) component the new scss file. Our components (top
level) also have to import the bootstrap.css from it's location under
``node_modules``.

configuration
.............

To add a new configuration parameter for the react apps, it has to be added in
2 different places.

 * The default setting is set in Python format, in
   `eduid_webapp.jsconfig.settings.front`
 * This default can be overriden with a setting for etcd, added in the file
   `eduid-developer/etcd/conf.yaml`, under the key `/eduid/webapp/jsapps`.

Development of a component
..........................

TODO

Communication between front and back
------------------------------------

Data sent from server to the browser is json with the format of redux actions,
as described in `this proposed standard
<https://github.com/acdlite/flux-standard-action>`_. Basically, a message has
a schema:

 * `type` (required) a string identyfying the action.
 * `payload` (optional) a structure with arbitrary data.
 * `error` (optional) a structure with arbitrary error data.

Available actions are located at `eduid-html/react/src/actions/`.

Data sent from the browserto the server is in the form of
json data.

The format for the action type names will be
`METHOD_BLUEPRINTNAME_URLRULE` for the triggering action (only ever produced in
the browser), and for the failure/success consequent actions, that can
originate either in the server or in the browser, the format will be the same
but appending either `_FAIL` or `_SUCCESS`. The canonical procedure to
generate action type names can be checked out in
`here <https://github.com/SUNET/eduid-common/blob/new_utils/src/eduid_common/api/utils.py#L116>`_.


Docker
------

Each microservice is deployed in a docker container. There is a base Dockerfile
for microservices at ``eduid-webapp/docker/``. The Dockerfile for each
microservice is kept in a subdirectory in the eduid-dockerfiles repository, and
they basically extend the base Dockerfile to inject a script to configure and
run the app within a gunicorn wsgi server (e.g. see
eduid-dockerfiles/eduid-personal/start.sh``.) Any new distribution dependency for
new apps are added to the base Dockerfile at ``eduid-webapp/docker/setup.sh``.

Container configurations are kept in the eduid-developer repository. The
configuration for the services is provided by a etcd container, and is kept at
``eduid-developer/etcd/conf.yaml``.

The configuration for the containers is managed by docker-compose and is kept
in ``eduid-developer/eduid/compose.yml``.

To update the images for the docker environment we run, from the root of the
eduid-developer repo::

  docker-compose -f eduid/compose.yml pull

The docker environment is started by a script in ``eduid-developer/start.sh``.
