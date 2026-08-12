from eduid.queue.helpers import Jinja2Env

__author__ = "lundberg"


class TestJinja2EnvAutoescape:
    """
    Regression test for stored HTML injection: outbound mail templates must be
    autoescaped regardless of whether the template filename uses a ".html." infix
    (group_invite_email.html.jinja2) or not (eduid_invite_mail_html.jinja2).
    """

    def setup_method(self) -> None:
        self.jinja2 = Jinja2Env()

    def test_group_invite_email_escapes_html_infix_template(self) -> None:
        payload = "<script>alert(1)</script>"
        with self.jinja2.select_language("en") as env:
            rendered = env.jinja2_env.get_template("group_invite_email.html.jinja2").render(
                site_name="Test",
                site_url="https://example.com",
                group_display_name=payload,
                group_invite_url="https://example.com/invite",
            )
        assert payload not in rendered
        assert "&lt;script&gt;" in rendered

    def test_eduid_invite_mail_escapes_underscore_html_template(self) -> None:
        payload = "<script>alert(1)</script>"
        with self.jinja2.select_language("en") as env:
            rendered = env.jinja2_env.get_template("eduid_invite_mail_html.jinja2").render(
                invite_link="https://example.com/invite",
                inviter_name=payload,
            )
        assert payload not in rendered
        assert "&lt;script&gt;" in rendered

    def test_txt_templates_are_not_escaped(self) -> None:
        payload = "<script>alert(1)</script>"
        with self.jinja2.select_language("en") as env:
            rendered = env.jinja2_env.get_template("eduid_invite_mail_txt.jinja2").render(
                invite_link="https://example.com/invite",
                inviter_name=payload,
            )
        assert payload in rendered
