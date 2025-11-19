from pydantic import HttpUrl

from eduid.common.config.base import EduIDBaseAppConfig, ErrorsConfigMixin, FrontendActionMixin, Pysaml2SPConfigMixin
from eduid.common.models.generic import HttpUrlAdapter


class AuthnConfig(EduIDBaseAppConfig, ErrorsConfigMixin, Pysaml2SPConfigMixin, FrontendActionMixin):
    """
    Configuration for the authn app
    """

    app_name: str = "authn"
    server_name: str = "authn"
    signup_authn_success_redirect_url: HttpUrl = HttpUrlAdapter.validate_python("https://eduid.se/profile/")
    signup_authn_failure_redirect_url: HttpUrl = HttpUrlAdapter.validate_python("https://eduid.se/profile/")
    fallback_frontend_action_redirect_url: HttpUrl = HttpUrlAdapter.validate_python("https://eduid.se/profile/")
    saml2_login_redirect_url: str
    saml2_logout_redirect_url: str
    saml2_strip_saml_user_suffix: str
