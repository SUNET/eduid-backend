from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from flask import current_app, make_response, redirect, url_for
from werkzeug.datastructures import MultiDict
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.clients.oidc_client.base import OidcCallback, OidcRpError, OidcRpIssMismatchError
from eduid.common.misc.timeutil import utc_now

if TYPE_CHECKING:
    from eduid.common.clients.oidc_client.base import OidcRpClient
    from eduid.webapp.common.session.namespaces import OIDCState, RP_AuthnRequest


class EduidErrorsContext(StrEnum):
    SAML_RESPONSE_FAIL = "saml_response_fail"
    SAML_REQUEST_MISSING_IDP = "saml_request_missing_idp"
    SAML_MISSING_ATTRIBUTE = "saml_missing_attribute"
    SAML_RESPONSE_UNSOLICITED = "saml_response_unsolicited"
    OIDC_RESPONSE_UNSOLICITED = "oidc_response_unsolicited"
    OIDC_RESPONSE_FAIL = "oidc_response_fail"


def goto_errors_response(
    errors_url: str, ctx: EduidErrorsContext, rp: str, tid: str | None = None, now: datetime | None = None
) -> WerkzeugResponse:
    if now is None:
        now = utc_now()
    if tid is None:
        tid = "ERRORURL_TID"
    fmt_url = errors_url.format(
        ERRORURL_CODE="EDUID_ERROR",
        ERRORURL_RP=rp,
        ERRORURL_CTX=ctx.value,
        ERRORURL_TID=tid,
        ERRORURL_TS=int(now.timestamp()),
    )
    return redirect(fmt_url)


def oidc_response_rejected(err: OidcRpError, callback_endpoint: str) -> WerkzeugResponse:
    """
    Reject a malformed or ambiguous OIDC authorization response, or one with an iss mismatch, that can not be
    attributed to exactly one unhandled pending authn (see pending_authn_for_rejected_callback).

    The pending authns are left unchanged. The rejection itself is logged once by the OidcRpClient (INFO for a
    malformed response, WARNING for an iss mismatch), not here.

    :param err: The error from OidcRpClient.parse_callback
    :param callback_endpoint: Flask endpoint of the authn callback view, e.g. "orcid.authn_callback"
    :returns: 400 if no errors_url_template is configured, otherwise a redirect to the errors page
    """
    current_app.stats.count(name="authn_response_rejected")  # type: ignore[attr-defined]
    errors_url_template: str | None = current_app.conf.errors_url_template  # type: ignore[attr-defined]
    if not errors_url_template:
        return make_response("Bad authn response", 400)
    return goto_errors_response(
        errors_url=errors_url_template,
        ctx=EduidErrorsContext.OIDC_RESPONSE_FAIL,
        rp=url_for(callback_endpoint, _external=True),
    )


def pending_authn_for_rejected_callback(
    args: "MultiDict[str, str]", authns: "Mapping[OIDCState, RP_AuthnRequest]"
) -> "RP_AuthnRequest | None":
    """
    Find the pending authn a rejected callback belongs to, if it is attributable to exactly one.

    :param args: The query arguments of the rejected callback
    :param authns: The authn requests in the session namespace of the calling app
    :returns: The authn if there is exactly one non-empty state matching an unhandled authn, otherwise None
    """
    states = args.getlist("state")
    if len(states) != 1 or not states[0]:
        return None
    authn_req = authns.get(cast("OIDCState", states[0]))
    if authn_req is None or authn_req.callback_handled:
        return None
    return authn_req


def oidc_response_rejected_terminal(
    err: OidcRpError, authn_req: "RP_AuthnRequest", *, status: str, finish_url: str
) -> WerkzeugResponse:
    """
    Reject a malformed OIDC authorization response that belongs to a known pending authn, and terminate that authn
    as failed like a provider error response. Sets authn_req.callback_handled itself, so the authn is
    consumed whichever way the caller reached this helper.

    :param err: The error from OidcRpClient.parse_callback
    :param authn_req: The pending authn the response belongs to
    :param status: Status to set on the authn, the authorization error message of the app
    :param finish_url: Formatted finish url of the authn
    :returns: A redirect to finish_url
    """
    current_app.stats.count(name="authn_response_rejected")  # type: ignore[attr-defined]
    authn_req.callback_handled = True
    authn_req.error = True
    authn_req.status = status
    return redirect(finish_url)


@dataclass(frozen=True)
class AcceptedCallback:
    """A parsed callback that matches an unanswered pending authn."""

    authn_req: "RP_AuthnRequest"
    callback: OidcCallback


@dataclass(frozen=True)
class RejectedCallback:
    """A rejected callback that is attributable to exactly one unanswered pending authn."""

    authn_req: "RP_AuthnRequest"
    error: OidcRpError


def resolve_oidc_callback(
    oidc_client: "OidcRpClient",
    args: "MultiDict[str, str]",
    authns: "Mapping[OIDCState, RP_AuthnRequest]",
    callback_endpoint: str,
) -> WerkzeugResponse | AcceptedCallback | RejectedCallback:
    """
    Parse an OIDC authorization response and match it to a pending authn of the calling app.

    Does not modify any authn. The caller consumes the returned authn_req (sets callback_handled).

    :param oidc_client: The OIDC RP client of the calling app
    :param args: The query arguments of the callback
    :param authns: The authn requests in the session namespace of the calling app
    :param callback_endpoint: Flask endpoint of the authn callback view, e.g. "orcid.authn_callback"
    :returns: A response to return right away if the callback is rejected without being attributable to an authn
        or does not match an unanswered authn, otherwise the matched authn with the parsed callback or the
        rejection error
    """
    try:
        callback = oidc_client.parse_callback(args)
    except OidcRpError as err:
        # Counted here, once per request, whichever way the rejection is handled below
        if isinstance(err, OidcRpIssMismatchError):
            current_app.stats.count(name="authn_iss_mismatch")  # type: ignore[attr-defined]
        # A rejected response is terminal for the pending authn it belongs to, if it is attributable to exactly one
        # unhandled authn. Otherwise it is rejected without touching any authn.
        rejected_authn = pending_authn_for_rejected_callback(args, authns)
        if rejected_authn is None:
            return oidc_response_rejected(err, callback_endpoint)
        return RejectedCallback(authn_req=rejected_authn, error=err)

    # The state is only matched against the authn requests in this session, that is the state binding (CSRF check)
    oidc_state = cast("OIDCState", callback.state) if callback.state else None
    authn_req = authns.get(oidc_state) if oidc_state is not None else None
    if authn_req is None or authn_req.callback_handled:
        # Perhaps an authn response received out of order - abort without destroying state
        # (User makes two requests, A and B. Response B arrives, user is happy and proceeds with their work.
        #  Then response A arrives late. Just silently abort, no need to mess up the users' session.)
        current_app.logger.info(
            f"Response {oidc_state} does not match an unanswered request in session, redirecting user to eduID Errors page"
        )
        errors_url_template: str | None = current_app.conf.errors_url_template  # type: ignore[attr-defined]
        if not errors_url_template:
            return make_response("Unknown authn response", 400)
        return goto_errors_response(
            errors_url=errors_url_template,
            ctx=EduidErrorsContext.OIDC_RESPONSE_UNSOLICITED,
            rp=url_for(callback_endpoint, _external=True),
        )
    return AcceptedCallback(authn_req=authn_req, callback=callback)
