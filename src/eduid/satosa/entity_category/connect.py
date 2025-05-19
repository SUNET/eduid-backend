__author__ = "bjorn"

from typing import Any

R_AND_S = [
    "eduPersonPrincipalName",
    "eduPersonUniqueID",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
]

GEANT_COCO = [
    "pairwise-id",
    "subject-id",
    "eduPersonTargetedID",
    "eduPersonPrincipalName",
    "eduPersonOrcid",
    "norEduPersonNIN",
    "personalIdentityNumber",
    "schacDateOfBirth",
    "mail",
    "mailLocalAddress",
    "displayName",
    "cn",
    "givenName",
    "sn",
    "norEduPersonLegalName",
    "eduPersonAssurance",
    "eduPersonScopedAffiliation",
    "eduPersonAffiliation",
    "o",
    "norEduOrgAcronym",
    "c",
    "co",
    "schacHomeOrganization",
    "schacHomeOrganizationType",
]

REFEDS_COCO = GEANT_COCO  # for now these two are identical

MYACADEMICID_ESI = ["schacPersonalUniqueCode"]

REFEDS_PERSONALIZED_ACCESS = [
    "subject-id",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "eduPersonScopedAffiliation",
    "eduPersonAssurance",
    "schacHomeOrganization",
]

REFEDS_PSEUDONYMOUS_ACCESS = [
    "pairwise-id",
    "eduPersonScopedAffiliation",
    "eduPersonAssurance",
    "schacHomeOrganization",
]

REFEDS_ANONYMOUS_ACCESS = [
    "eduPersonScopedAffiliation",
    "schacHomeOrganization",
]

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

# These give you access to information
RESEARCH_AND_SCHOLARSHIP = "http://refeds.org/category/research-and-scholarship"
COCOv1 = "http://www.geant.net/uri/dataprotection-code-of-conduct/v1"
COCOv2 = "https://refeds.org/category/code-of-conduct/v2"
ESI = "https://myacademicid.org/entity-categories/esi"
PERSONALIZED = "https://refeds.org/category/personalized"
PSEUDONYMOUS = "https://refeds.org/category/pseudonymous"
ANONYMOUS = "https://refeds.org/category/anonymous"
# For Connect only
TCSSERVERv1 = "https://sunet.se/category/tcs/v1"


RELEASE = {
    "": [],
    RESEARCH_AND_SCHOLARSHIP: R_AND_S,
    COCOv1: GEANT_COCO,
    COCOv2: REFEDS_COCO,
    ESI: MYACADEMICID_ESI,
    (ESI, COCOv1): MYACADEMICID_ESI + GEANT_COCO,
    (ESI, COCOv2): MYACADEMICID_ESI + REFEDS_COCO,
    TCSSERVERv1: TCS_SERVER,
}

ONLY_REQUIRED = {
    COCOv1: True,
    COCOv2: True,
    (ESI, COCOv1): True,
    (ESI, COCOv2): True,
    TCSSERVERv1: True,
}

# ruff: noqa: ERA001
# These restrictions are parsed (and validated) into a list of saml2.assertion.EntityCategoryRule instances.
RESTRICTIONS: list[dict[str, Any]] = [
    {
        "match": {
            "required": [PERSONALIZED],
            "conflicts": [PSEUDONYMOUS, ANONYMOUS],
        },
        "attributes": REFEDS_PERSONALIZED_ACCESS,
    },
    {
        "match": {
            "required": [PSEUDONYMOUS],
            "conflicts": [ANONYMOUS],
        },
        "attributes": REFEDS_PSEUDONYMOUS_ACCESS,
    },
    {
        "match": {
            "required": [ANONYMOUS],
        },
        "attributes": REFEDS_ANONYMOUS_ACCESS,
    },
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
