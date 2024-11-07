from pathlib import PurePath
from unittest import TestCase

from eduid.workers.msg.utils import load_template


class TestUtils(TestCase):
    def setUp(self) -> None:
        self.template_dir = str(PurePath(__file__).with_name("data"))
        self.msg_dict = {"name": "Godiskungen", "admin": "Testadmin"}

    def test_load_template_missing(self) -> None:
        with self.assertRaises(RuntimeError):
            load_template(self.template_dir, "apa.tmpl", self.msg_dict, "sv_SE")

    def test_load_and_render_template(self) -> None:
        message = load_template(self.template_dir, "test.tmpl", self.msg_dict, "sv_SE")
        self.assertEqual(message, "Sender is {}, recipient is {}".format(self.msg_dict["admin"], self.msg_dict["name"]))
