# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.{{cookiecutter.directory_name}}.app import init_{{cookiecutter.directory_name}}_app

__author__ = '{{cookiecutter.author}}'


class {{cookiecutter.class_name}}Tests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super({{cookiecutter.class_name}}Tests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return {{cookiecutter.directory_name}}_app('testing', config)

    def update_config(self, config):
        return config

    def tearDown(self):
        super({{cookiecutter.class_name}}Tests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()