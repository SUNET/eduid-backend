import importlib.util
import logging
import os.path
import sys
from typing import Optional, Sequence

from saml2 import server
from saml2.config import SPConfig
from saml2.typing import SAMLHttpArgs

from eduid.common.config.base import EduIDBaseAppConfig, FrontendAction, FrontendActionMixin
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.userdb.credentials import Credential
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import SP_AuthnRequest

logger = logging.getLogger(__name__)


def get_saml2_config(module_path: str, name="SAML_CONFIG") -> SPConfig:
    """Load SAML2 config file, in the form of a Python module."""
    spec = importlib.util.spec_from_file_location("saml2_settings", module_path)
    if spec is None:
        raise RuntimeError(f"Failed loading saml2_settings module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore

    conf = SPConfig()
    conf.load(module.__getattribute__(name))
    return conf


def get_location(http_info: SAMLHttpArgs) -> str:
    """Extract the redirect URL from a pysaml2 http_info object"""
    assert "headers" in http_info
    headers = http_info["headers"]

    assert len(headers) == 1
    header_name, header_value = headers[0]
    assert header_name == "Location"
    return header_value


def get_saml_attribute(session_info: SessionInfo, attr_name: str) -> Optional[list[str]]:
    """
    Get value from a SAML attribute received from the SAML IdP.

    session_info is a pysaml2 response.session_info(). This is a dictionary like
        {'mail': ['user@example.edu'],
         'eduPersonPrincipalName': ['gadaj-fifib@idp.example.edu']
      }

    :param session_info: SAML attributes received by pysaml2 client.
    :param attr_name: The attribute to look up
    :returns: Attribute values

    :type session_info: dict()
    :type attr_name: string()
    :rtype: [string()]
    """
    if "ava" not in session_info:
        raise ValueError("SAML attributes (ava) not found in session_info")

    attributes = session_info["ava"]

    logger.debug("SAML attributes received: %s" % attributes)

    # Look for the canonicalized attribute in the SAML assertion attributes
    for saml_attr, _ in attributes.items():
        if saml_attr.lower() == attr_name.lower():
            return attributes[saml_attr]
    return None


def no_authn_views(config: EduIDBaseAppConfig, paths: Sequence[str]) -> None:
    """
    :param config: Configuration to modify with extra no_authn_urls
    :param paths: Paths that does not require authentication
    """
    app_root = config.flask.application_root
    for path in paths:
        no_auth_regex = f"^{urlappend(app_root, path)!s}$"
        if no_auth_regex not in config.no_authn_urls:
            config.no_authn_urls.append(no_auth_regex)
    return None


def check_previous_identification(session_ns: TimestampedNS) -> Optional[str]:
    """
    Check that the user, though not properly authenticated, has been recognized
    by some app with access to the shared session
    Must be called within a request context.

    Used after signup or for idp actions.

    :return: The eppn in case the check is successful, None otherwise
    """
    from eduid.webapp.common.session import session

    eppn = session.common.eppn
    logger.debug(f"Trying to authenticate user {eppn} with timestamp {session_ns.ts}")
    # check that the eppn and timestamp have been set in the session
    if eppn is None or session_ns.ts is None:
        return None
    # check timestamp to make sure it is within -300..900
    now = utc_now()
    # TODO: The namespace timestamp is a pretty underwhelming measure of the intent to allow this
    #       user to continue doing what they are doing. Do something better.
    if (session_ns.ts < now - timedelta(seconds=300)) or (session_ns.ts > now + timedelta(seconds=900)):
        delta = (now - session_ns.ts).total_seconds()
        logger.error(f"Auth token timestamp {session_ns.ts} out of bounds ({delta} seconds from {now})")
        return None
    return eppn


def init_pysaml2(cfgfile: str) -> server.Server:
    """
    Initialization of PySAML2.

    :return:
    """
    old_path = sys.path
    cfgdir = os.path.dirname(cfgfile)
    if cfgdir:
        # add directory part to sys.path, since pysaml2 'import's it's config
        sys.path = [cfgdir] + sys.path
        cfgfile = os.path.basename(cfgfile)

    try:
        return server.Server(cfgfile)
    finally:
        # restore path
        sys.path = old_path


def get_authn_for_action(config: FrontendActionMixin, frontend_action: FrontendAction) -> Optional[SP_AuthnRequest]:
    authn_params = config.frontend_action_authn_parameters.get(frontend_action)
    if authn_params is None:
        raise BadConfiguration(f"No authn parameters for frontend action {frontend_action}")

    authn = session.authn.sp.get_authn_for_frontend_action(frontend_action)
    if not authn and authn_params.allow_login_auth:
        authn = session.authn.sp.get_authn_for_frontend_action(FrontendAction.LOGIN)
        # check for old login actions until we remove them
        if not authn and authn_params.allow_login_auth:
            authn = session.authn.sp.get_authn_for_frontend_action(FrontendAction.OLD_LOGIN)
    return authn


def validate_authn_for_action(
    config: FrontendActionMixin,
    frontend_action: FrontendAction,
    credential_used: Optional[Credential] = None,
) -> AuthnActionStatus:
    """ """
    authn_params = config.frontend_action_authn_parameters.get(frontend_action)
    if authn_params is None:
        raise BadConfiguration(f"No authn parameters for frontend action {frontend_action}")

    authn = get_authn_for_action(config=config, frontend_action=frontend_action)

    if not authn or not authn.authn_instant:
        logger.info("No authentication found")
        logger.debug(f"frontend action: {frontend_action}, allow_login_auth={authn_params.allow_login_auth}")
        return AuthnActionStatus.NOT_FOUND

    if authn.consumed:
        logger.info("The authentication presented has already been consumed")
        return AuthnActionStatus.CONSUMED

    delta = utc_now() - authn.authn_instant
    logger.debug(f"Authentication age {delta}")
    if delta > authn_params.max_age:
        logger.info(f"Authentication age {delta} too old")
        return AuthnActionStatus.STALE

    if authn.req_authn_ctx:
        if authn.asserted_authn_ctx not in authn.req_authn_ctx:
            logger.info("Authentication requires a different authentication context")
            logger.info(f"Expected accr: {authn.req_authn_ctx} got: {authn.asserted_authn_ctx}")
            return AuthnActionStatus.WRONG_ACCR

    # specific check for MFA to be able to use login actions
    if authn_params.force_mfa and len(authn.credentials_used) < 2:
        logger.info("Authentication requires MFA")
        logger.info(f"Expected at least 2 credentials got: {len(authn.credentials_used)}")
        return AuthnActionStatus.NO_MFA

    if credential_used and not credential_recently_used(
        credential=credential_used, action=authn, max_age=int(authn_params.max_age.total_seconds())
    ):
        logger.info(f"Credential {credential_used} has not been used recently")
        return AuthnActionStatus.CREDENTIAL_NOT_RECENTLY_USED

    return AuthnActionStatus.OK


def credential_recently_used(credential: Credential, action: Optional[SP_AuthnRequest], max_age: int) -> bool:
    logger.debug(f"Checking if credential {credential} has been used in the last {max_age} seconds")
    if action and credential.key in action.credentials_used:
        if action.authn_instant is not None:
            age = (utc_now() - action.authn_instant).total_seconds()
            if 0 < age < max_age:
                logger.debug(f"Credential {credential} has been used recently")
                return True
    return False
