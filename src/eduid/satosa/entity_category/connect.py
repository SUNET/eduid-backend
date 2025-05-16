__author__ = "bjorn"

from typing import Any

TCS_SERVER = [
    "eduPersonPrincipalName",
    "givenName",
    "sn",
    "mail",
    "edupersonTargetedID",
    "eduPersonEntitlement",
    "schacHomeOrganization",
]

TCSSERVERv1 = "https://sunet.se/category/tcs/v1"


RELEASE = {
    "": [],
    TCSSERVERv1: TCS_SERVER,
}

ONLY_REQUIRED = {
    TCSSERVERv1: True,
}

# ruff: noqa: ERA001
# These restrictions are parsed (and validated) into a list of saml2.assertion.EntityCategoryRule instances.
RESTRICTIONS: list[dict[str, Any]] = [
    # Example of conversion of some of the rules in RELEASE to this new format:
    #
    # {
    #     "match": {
    #         "required": [COCOv1],
    #     },
    #     "attributes": GEANT_COCO,
    #     "only_required": True,
    # },
    # {
    #     "match": {
    #         "required": [ESI, COCOv1],
    #     },
    #     "attributes": MYACADEMICID_ESI + GEANT_COCO,
    #     "only_required": True,
    # },
]
