# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Literal, Mapping, Optional, cast, overload

from flask import Blueprint
from flask import current_app as flask_current_app
from flask import jsonify
from flask.wrappers import Response

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.webapp.common.api.checks import CheckResult
from eduid.webapp.common.api.utils import get_from_current_app

if TYPE_CHECKING:
    from eduid.webapp.common.api.app import EduIDBaseApp

    current_app = cast(EduIDBaseApp, flask_current_app)
else:
    current_app = flask_current_app

logger = logging.getLogger(__name__)

status_views = Blueprint("status", __name__, url_prefix="/status")


@dataclass
class SimpleCacheItem:
    expire_time: datetime
    data: Mapping[str, Any]


SIMPLE_CACHE: Dict[str, SimpleCacheItem] = dict()


@overload
def cached_json_response(key: str, data: dict[str, Any]) -> Response:
    ...


@overload
def cached_json_response(key: str, data: Literal[None]) -> Optional[Response]:
    ...


def cached_json_response(key: str, data: Optional[dict[str, Any]] = None) -> Optional[Response]:
    cache_for_seconds = get_from_current_app("conf", EduIDBaseAppConfig).status_cache_seconds
    now = datetime.utcnow()
    if SIMPLE_CACHE.get(key) is not None:
        if now < SIMPLE_CACHE[key].expire_time:
            if get_from_current_app("debug", bool):
                logger.debug(f"Returned cached response for {key}" f" {now} < {SIMPLE_CACHE[key].expire_time}")
            response = jsonify(SIMPLE_CACHE[key].data)
            response.headers.add("Expires", SIMPLE_CACHE[key].expire_time.strftime("%a, %d %b %Y %H:%M:%S UTC"))
            response.headers.add("Cache-Control", f"public,max-age={cache_for_seconds}")
            return response

    # Allow for the function to be called with no data so we can check for a cached response
    # before running the checks
    if data is None:
        return None

    expires = now + timedelta(seconds=cache_for_seconds)
    response = jsonify(data)
    response.headers.add("Expires", expires.strftime("%a, %d %b %Y %H:%M:%S UTC"))
    response.headers.add("Cache-Control", f"public,max-age={cache_for_seconds}")
    SIMPLE_CACHE[key] = SimpleCacheItem(expire_time=expires, data=data)
    if current_app.debug:
        logger.debug(f"Cached response for {key} until {expires}")
    return response


@status_views.route("/healthy", methods=["GET"])
def health_check() -> Response:
    response = cached_json_response("health_check", None)
    if response:
        return response

    res: CheckResult = current_app.run_health_checks()
    # Value of status crafted for grepabilty, trailing underscore intentional
    if res.healthy is True:
        res.status = f"STATUS_OK_{current_app.name}_"
        res.reason = "Databases and task queues tested OK"
    else:
        res.status = f"STATUS_FAIL_{current_app.name}_"

    return cached_json_response("health_check", asdict(res))


@status_views.route("/sanity-check", methods=["GET"])
def sanity_check() -> Response:
    response = cached_json_response("sanity_check", None)
    if response:
        return response
    # TODO: Do checks here
    return cached_json_response("sanity_check", {})
