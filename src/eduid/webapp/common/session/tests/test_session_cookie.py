from eduid.webapp.common.session.meta import SessionMeta


class TestSessionCookie:
    def test_from_cookie(self) -> None:
        app_secret = "supersecretkey"
        cookie_val = (
            "aZPXP25Y5MUIM6APRRY3QEDTOHLAAKDEBLRFU5AOEPIPPW5L7UVVX"
            "3BSEJEYVTKYD5OJNOX5GECL7OD5FZV4BWFE7KCCHG36SGFMNIBDY"
        )
        token = SessionMeta.from_cookie(cookie_val, app_secret)
        assert token.session_id == "cbeefd771d6510cf01f18e37020e6e3ac0050c815c4b4e81c47a1efb757fa56b"
