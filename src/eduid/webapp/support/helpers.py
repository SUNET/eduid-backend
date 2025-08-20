from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from flask import abort
from werkzeug import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.userdb.db import TUserDbDocument
from eduid.webapp.common.api.utils import get_user, has_user_logged_in_with_mfa
from eduid.webapp.support.app import current_support_app as current_app

__author__ = "lundberg"


def get_credentials_aux_data(user: User) -> list[TUserDbDocument]:
    """
    :param user: User object
    :return: Augmented credentials list
    """
    credentials: list[TUserDbDocument] = []
    for credential in user.credentials.to_list():
        credential_dict = credential.to_dict()
        credential_dict["type"] = credential.__class__.__name__
        credential_info = current_app.support_authn_db.get_credential_info(credential.key)
        if credential_info:
            # Add success_ts
            credential_dict["success_ts"] = credential_info["success_ts"]
        credentials.append(credential_dict)
    return credentials


TRequireSupportPersonnelResult = TypeVar("TRequireSupportPersonnelResult")


def require_support_personnel(
    f: Callable[..., TRequireSupportPersonnelResult],
) -> Callable[..., TRequireSupportPersonnelResult]:
    @wraps(f)
    def require_support_decorator(*args: Any, **kwargs: Any) -> TRequireSupportPersonnelResult:
        user = get_user()
        # If the logged in user is whitelisted then we
        # pass on the request to the decorated view
        # together with the eppn of the logged in user.
        if user and user.eppn in current_app.conf.support_personnel:
            kwargs["support_user"] = user
            return f(*args, **kwargs)
        current_app.logger.warning(f"{user} not in support personnel whitelist: {current_app.conf.support_personnel}")
        # Anything else is considered as an unauthorized request
        abort(403)

    return require_support_decorator


TRequireLoginWithMFAResult = TypeVar("TRequireLoginWithMFAResult")


def require_login_with_mfa(
    f: Callable[..., TRequireLoginWithMFAResult],
) -> Callable[..., TRequireLoginWithMFAResult | WerkzeugResponse]:
    @wraps(f)
    def require_login_with_mfa_decorator(*args: Any, **kwargs: Any) -> TRequireLoginWithMFAResult | WerkzeugResponse:
        if has_user_logged_in_with_mfa():
            return f(*args, **kwargs)
        resp = WerkzeugResponse("OK", 200)
        resp.headers["HX-Redirect"] = current_app.conf.authn_service_url_login
        return resp

    return require_login_with_mfa_decorator
