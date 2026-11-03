import logging
from typing import cast

import pytest
from flask import Flask
from werkzeug.datastructures import MultiDict

from eduid.common.clients.oidc_client.base import (
    CallbackParams,
    OidcCallback,
    OidcRpClient,
    OidcRpError,
    OidcRpIssMismatchError,
)
from eduid.common.config.base import FrontendAction
from eduid.webapp.common.api.errors import (
    AcceptedCallback,
    RejectedCallback,
    oidc_response_rejected,
    oidc_response_rejected_terminal,
    pending_authn_for_rejected_callback,
    resolve_oidc_callback,
)
from eduid.webapp.common.session.namespaces import OIDCState, RP_AuthnRequest


def _app(errors_url_template: str | None) -> Flask:
    app = Flask(__name__)

    class _Stats:
        def __init__(self) -> None:
            self.counted: list[str] = []

        def count(self, name: str) -> None:
            self.counted.append(name)

    class _Conf:
        pass

    conf = _Conf()
    conf.errors_url_template = errors_url_template  # type: ignore[attr-defined]
    app.conf = conf  # type: ignore[attr-defined]
    app.stats = _Stats()  # type: ignore[attr-defined]
    app.add_url_rule("/cb", endpoint="x.cb", view_func=lambda: "")
    return app


def test_oidc_response_rejected_no_template(caplog: pytest.LogCaptureFixture) -> None:
    app = _app(None)
    with app.test_request_context(), caplog.at_level(logging.DEBUG):
        res = oidc_response_rejected(OidcRpError("bad thing"), "x.cb")
    assert res.status_code == 400
    assert res.get_data(as_text=True) == "Bad authn response"
    assert app.stats.counted == ["authn_response_rejected"]  # type: ignore[attr-defined]
    assert [(r.levelno, r.getMessage()) for r in caplog.records if "bad thing" in r.getMessage()] == [
        (logging.INFO, "Authorization response rejected: bad thing")
    ]


def test_oidc_response_rejected_iss_mismatch_is_warning(caplog: pytest.LogCaptureFixture) -> None:
    app = _app(None)
    with app.test_request_context(), caplog.at_level(logging.DEBUG):
        oidc_response_rejected(OidcRpIssMismatchError("iss mismatch"), "x.cb")
    assert [r.levelno for r in caplog.records if "iss mismatch" in r.getMessage()] == [logging.WARNING]


def test_oidc_response_rejected_redirect() -> None:
    app = _app("https://errors.example/?ctx={ERRORURL_CTX}&rp={ERRORURL_RP}")
    with app.test_request_context():
        res = oidc_response_rejected(OidcRpError("bad"), "x.cb")
    assert res.status_code == 302
    assert "ctx=oidc_response_fail" in res.headers["Location"]
    assert "rp=http://localhost/cb" in res.headers["Location"]


def _authn(state: str = "S", *, handled: bool = False) -> RP_AuthnRequest:
    return RP_AuthnRequest(
        authn_id=OIDCState(state),
        frontend_action=FrontendAction.VERIFY_IDENTITY,
        finish_url="https://fe/{app_name}/{authn_id}",
        callback_handled=handled,
    )


def test_pending_authn_single_state() -> None:
    authn = _authn()
    found = pending_authn_for_rejected_callback(MultiDict([("state", "S"), ("code", "C")]), {OIDCState("S"): authn})
    assert found is authn


@pytest.mark.parametrize(
    "args",
    [
        [("state", "S"), ("state", "S"), ("code", "C")],
        [("state", ""), ("code", "C")],
        [("code", "C")],
        [("state", "unknown"), ("code", "C")],
    ],
)
def test_pending_authn_not_attributable(args: list[tuple[str, str]]) -> None:
    authn = _authn()
    before = authn.model_copy()
    assert pending_authn_for_rejected_callback(MultiDict(args), {OIDCState("S"): authn}) is None
    assert authn == before


def test_pending_authn_already_handled() -> None:
    authn = _authn(handled=True)
    before = authn.model_copy()
    assert pending_authn_for_rejected_callback(MultiDict([("state", "S")]), {OIDCState("S"): authn}) is None
    assert authn == before


def test_oidc_response_rejected_terminal(caplog: pytest.LogCaptureFixture) -> None:
    app = _app(None)
    authn = _authn()
    authn.callback_handled = True
    with app.test_request_context(), caplog.at_level(logging.DEBUG):
        res = oidc_response_rejected_terminal(
            OidcRpError("bad thing"),
            authn,
            status="some.error",
            finish_url=authn.formatted_finish_url(app_name="testapp"),
        )
    assert res.status_code == 302
    assert res.headers["Location"] == "https://fe/testapp/S"
    assert authn.error is True
    assert authn.status == "some.error"
    assert authn.consumed is False
    assert app.stats.counted == ["authn_response_rejected"]  # type: ignore[attr-defined]
    assert [(r.levelno, r.getMessage()) for r in caplog.records if "bad thing" in r.getMessage()] == [
        (logging.INFO, "Authorization response rejected: bad thing")
    ]


def test_oidc_response_rejected_terminal_sets_callback_handled() -> None:
    app = _app(None)
    authn = _authn()
    assert authn.callback_handled is False
    with app.test_request_context():
        oidc_response_rejected_terminal(
            OidcRpError("bad"), authn, status="some.error", finish_url="https://fe/testapp/S"
        )
    assert authn.callback_handled is True


class _FakeClient:
    def __init__(self, result: OidcCallback | OidcRpError) -> None:
        self.result = result

    def parse_callback(self, params: CallbackParams | object) -> OidcCallback:
        if isinstance(self.result, OidcRpError):
            raise self.result
        return self.result


def _client(result: OidcCallback | OidcRpError) -> OidcRpClient:
    return cast(OidcRpClient, _FakeClient(result))


def _callback(state: str | None = "S") -> OidcCallback:
    return OidcCallback(state=state, code="C", error=None, error_known=False, error_description_safe=None)


_ERRORS_URL = "https://errors.example/?ctx={ERRORURL_CTX}&rp={ERRORURL_RP}"


def test_resolve_accepted() -> None:
    app = _app(_ERRORS_URL)
    authn = _authn()
    cb = _callback()
    with app.test_request_context():
        res = resolve_oidc_callback(_client(cb), MultiDict([("state", "S")]), {OIDCState("S"): authn}, "x.cb")
    assert isinstance(res, AcceptedCallback)
    assert res.authn_req is authn
    assert res.callback is cb
    assert authn.callback_handled is False
    assert app.stats.counted == []  # type: ignore[attr-defined]


def test_resolve_rejected_attributable() -> None:
    app = _app(_ERRORS_URL)
    authn = _authn()
    err = OidcRpError("bad")
    with app.test_request_context():
        res = resolve_oidc_callback(_client(err), MultiDict([("state", "S")]), {OIDCState("S"): authn}, "x.cb")
    assert isinstance(res, RejectedCallback)
    assert res.authn_req is authn
    assert res.error is err
    assert authn.callback_handled is False
    assert not authn.error
    assert app.stats.counted == []  # type: ignore[attr-defined]


def test_resolve_iss_mismatch_attributable_counted_once() -> None:
    app = _app(_ERRORS_URL)
    authn = _authn()
    err = OidcRpIssMismatchError("authorization response iss mismatch")
    with app.test_request_context():
        res = resolve_oidc_callback(_client(err), MultiDict([("state", "S")]), {OIDCState("S"): authn}, "x.cb")
    assert isinstance(res, RejectedCallback)
    assert res.error is err
    assert app.stats.counted == ["authn_iss_mismatch"]  # type: ignore[attr-defined]
    # the caller counts the rejection when it terminates the authn
    with app.test_request_context():
        oidc_response_rejected_terminal(res.error, res.authn_req, status="s", finish_url="https://f.example/")
    assert app.stats.counted == ["authn_iss_mismatch", "authn_response_rejected"]  # type: ignore[attr-defined]


@pytest.mark.parametrize(("template", "status"), [(None, 400), (_ERRORS_URL, 302)])
def test_resolve_iss_mismatch_not_attributable_counted_once(template: str | None, status: int) -> None:
    app = _app(template)
    with app.test_request_context():
        res = resolve_oidc_callback(
            _client(OidcRpIssMismatchError("authorization response iss mismatch")),
            MultiDict([("code", "C")]),
            {},
            "x.cb",
        )
    assert not isinstance(res, AcceptedCallback | RejectedCallback)
    assert res.status_code == status
    assert app.stats.counted == ["authn_iss_mismatch", "authn_response_rejected"]  # type: ignore[attr-defined]


@pytest.mark.parametrize(("template", "status"), [(None, 400), (_ERRORS_URL, 302)])
def test_resolve_rejected_not_attributable(template: str | None, status: int) -> None:
    app = _app(template)
    with app.test_request_context():
        res = resolve_oidc_callback(_client(OidcRpError("bad")), MultiDict([("code", "C")]), {}, "x.cb")
    assert not isinstance(res, AcceptedCallback | RejectedCallback)
    assert res.status_code == status
    assert app.stats.counted == ["authn_response_rejected"]  # type: ignore[attr-defined]
    assert "authn_iss_mismatch" not in app.stats.counted  # type: ignore[attr-defined]
    if status == 302:
        assert "ctx=oidc_response_fail" in res.headers["Location"]


@pytest.mark.parametrize(
    ("state", "handled"),
    [(None, False), ("", False), ("unknown", False), ("S", True)],
)
@pytest.mark.parametrize(("template", "status"), [(None, 400), (_ERRORS_URL, 302)])
def test_resolve_unsolicited(state: str | None, handled: bool, template: str | None, status: int) -> None:
    app = _app(template)
    authn = _authn(handled=handled)
    before = authn.model_copy()
    with app.test_request_context():
        res = resolve_oidc_callback(_client(_callback(state)), MultiDict(), {OIDCState("S"): authn}, "x.cb")
    assert not isinstance(res, AcceptedCallback | RejectedCallback)
    assert res.status_code == status
    assert authn == before
    assert app.stats.counted == []  # type: ignore[attr-defined]
    if status == 302:
        assert "ctx=oidc_response_unsolicited" in res.headers["Location"]
        assert "rp=http://localhost/cb" in res.headers["Location"]
