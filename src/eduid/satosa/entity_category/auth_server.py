__author__ = "lundberg"

from typing import Any

SUNET_AUTH_SERVER = [
    "eduPersonPrincipalName",
    "cn",
    "givenName",
    "sn",
    "eduPersonAssurance",
    "eduPersonEntitlement",
]

SUNETAUTHSERVERv1 = "https://sunet.se/category/sunet-auth-server/v1"


RELEASE = {
    "": [],
    SUNETAUTHSERVERv1: SUNET_AUTH_SERVER,
}

ONLY_REQUIRED = {
    SUNETAUTHSERVERv1: True,
}

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
