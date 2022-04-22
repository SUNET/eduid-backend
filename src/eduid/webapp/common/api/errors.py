from datetime import datetime
from enum import Enum
from typing import Optional

from flask import redirect
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now


class EduidErrorsContext(str, Enum):
    saml_response_fail = 'saml_response_fail'


def goto_errors_response(
    errors_url: str, ctx: EduidErrorsContext, rp: str, tid: Optional[str] = None, now: Optional[datetime] = None
) -> WerkzeugResponse:
    if now is None:
        now = utc_now()
    if tid is None:
        tid = 'ERRORURL_TID'
    fmt_url = errors_url.format(
        ERRORURL_CODE='EDUID_ERROR',
        ERRORURL_RP=rp,
        ERRORURL_CTX=ctx.value,
        ERRORURL_TID=tid,
        ERRORURL_TS=int(now.timestamp()),
    )
    return redirect(fmt_url)
