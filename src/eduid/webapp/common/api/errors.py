from datetime import datetime
from enum import StrEnum

from flask import redirect
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now


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
