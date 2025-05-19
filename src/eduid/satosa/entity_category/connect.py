__author__ = "bjorn"

from typing import Any
from saml2.entity_category.swamid import RELEASE, ONLY_REQUIRED, RESTRICTIONS

# For Connect only
TCS_SERVER = [
    "eduPersonPrincipalName",
    "givenName",
    "sn",
    "mail",
    "edupersonTargetedID",
    "eduPersonEntitlement",
    "schacHomeOrganization",
]

# For Connect only
TCSSERVERv1 = "https://sunet.se/category/tcs/v1"

RELEASE[TCSSERVERv1] = TCS_SERVER
ONLY_REQUIRED[TCSSERVERv1] = True
RESTRICTIONS = RESTRICTIONS