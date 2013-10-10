from unittest import TestCase
from eduid_msg.utils import load_template
from jinja2 import TemplateNotFound
import pkg_resources


class TestUtils(TestCase):
    def setUp(self):
        self.template_dir = pkg_resources.resource_filename(__name__, 'data')
        self.msg_dict = {
            'name': 'Godiskungen',
            'admin': 'Testadmin'
        }

    def test_load_template_missing(self):
        try:
            load_template(self.template_dir, 'apa.tmpl', self.msg_dict, 'sv_SE')
        except TemplateNotFound:
            pass

    def test_load_and_render_template(self):
        message = load_template(self.template_dir, 'test.tmpl', self.msg_dict, 'sv_SE')
        self.assertEqual(message, "Sender is %s, recipient is %s" % (self.msg_dict['admin'], self.msg_dict['name']))
