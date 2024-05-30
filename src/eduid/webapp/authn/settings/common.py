from typing import Mapping

from pydantic import Field

from eduid.common.config.base import EduIDBaseAppConfig, ErrorsConfigMixin, Pysaml2SPConfigMixin


class AuthnConfig(EduIDBaseAppConfig, ErrorsConfigMixin, Pysaml2SPConfigMixin):
    """
    Configuration for the authn app
    """

    app_name: str = "authn"
    server_name: str = "authn"
    signup_authn_success_redirect_url: str = "https://dashboard.eduid.se"
    signup_authn_failure_redirect_url: str = "https://dashboard.eduid.se"
    saml2_login_redirect_url: str
    saml2_logout_redirect_url: str
    saml2_strip_saml_user_suffix: str
