from eduid_common.session.session_cookie import SessionCookie


class TestSessionCookie:
    def test_from_cookie(self):
        app_secret = 'supersecretkey'
        cookie_val = (
            'a44ADOHJ2PGALYCWK5POYDDSFC4PALOAKLZFRIYQ5A2KLO4W76TCNRXG'
            'WY4RZRICL3LR22J35WCJAPRFPHUNL77ZXGOBT5ZOHWGRG3YTY'
        )
        token = SessionCookie.from_cookie(cookie_val, app_secret)
        assert token.session_id == 'e700371d3a7980bc0acaebdd818e45171e05b80a5e4b14621d0694b772dff4c4'
