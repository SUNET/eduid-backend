from unittest import TestCase

import pkg_resources

from eduid_msg.utils import load_template


class TestUtils(TestCase):
    def setUp(self):
        self.template_dir = pkg_resources.resource_filename(__name__, 'data')
        self.msg_dict = {'name': 'Godiskungen', 'admin': 'Testadmin'}

    def test_load_template_missing(self):
        with self.assertRaises(RuntimeError):
            load_template(self.template_dir, 'apa.tmpl', self.msg_dict, 'sv_SE')

    def test_load_and_render_template(self):
        message = load_template(self.template_dir, 'test.tmpl', self.msg_dict, 'sv_SE')
        self.assertEqual(message, "Sender is %s, recipient is %s" % (self.msg_dict['admin'], self.msg_dict['name']))
