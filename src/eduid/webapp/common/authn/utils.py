import importlib.util
import logging
import os.path
import sys
from datetime import timedelta
from typing import TYPE_CHECKING, Optional, Sequence

from saml2 import server
from saml2.config import SPConfig
from saml2.typing import SAMLHttpArgs

# From https://stackoverflow.com/a/39757388
# The TYPE_CHECKING constant is always False at runtime, so the import won't be evaluated, but mypy
# (and other type-checking tools) will evaluate the contents of that block.
from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session.namespaces import TimestampedNS

if TYPE_CHECKING:
    pass

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
