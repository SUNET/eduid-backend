import os

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/usr/bin"])
else:
    xmlsec_path = "/usr/bin/xmlsec1"

_hostname = "unittest-idp.example.edu"
IDP_BASE = f"https://{_hostname!s}"

here = os.path.dirname(__file__)
key_path = os.path.join(here, "idp-public-snakeoil.key")
cert_path = os.path.join(here, "idp-public-snakeoil.pem")

# attrmaps_path = os.path.join(here, '../../../attributemaps')
idp_metadata_path = os.path.join(here, "idp_metadata.xml")
swamid_sp_metadata_path = os.path.join(here, "swamid_sp_metadata.xml")
coco_sp_metadata_path = os.path.join(here, "coco_sp_metadata.xml")
esi_coco_sp_metadata_path = os.path.join(here, "esi_coco_sp_metadata.xml")

# IdP config
CONFIG = {
    "entityid": f"{IDP_BASE}/idp.xml",
    "description": "eduID UNITTEST identity provider",
    "service": {
        "idp": {
            "name": "eduID UNITTEST IdP",
            "scope": ["eduid.example.edu"],
            "endpoints": {
                "single_sign_on_service": [
                    (f"{IDP_BASE}/sso/redirect", BINDING_HTTP_REDIRECT),
                    (f"{IDP_BASE}/sso/post", BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    (f"{IDP_BASE}/slo/soap", BINDING_SOAP),
                    (f"{IDP_BASE}/slo/post", BINDING_HTTP_POST),
                    (f"{IDP_BASE}/slo/redirect", BINDING_HTTP_REDIRECT),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 5},
                    # Restrict to all attributes except norEduPersonNIN and personalIdentityNumber.
                    "attribute_restrictions": {
                        "pairwise-id": None,
                        "subject-id": None,
                        "c": None,
                        "cn": None,
                        "co": None,
                        "displayName": None,
                        "eduPersonAssurance": None,
                        "eduPersonEntitlement": None,
                        "eduPersonOrcid": None,
                        "eduPersonPrincipalName": None,
                        "eduPersonTargetedID": None,
                        "givenName": None,
                        "mail": None,
                        "mailLocalAddress": None,
                        "preferredLanguage": None,
                        "schacDateOfBirth": None,
                        "schacPersonalUniqueCode": None,
                        "sn": None,
                    },
                    "name_form": NAME_FORMAT_URI,
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    "entity_categories": ["swamid"],
                    "fail_on_missing_requested": False,  # Don't fail on unsatisfied RequiredAttributes
                },
                # Only release all attributes to SPs that have registrationAuthority "http://www.swamid.se/"
                "http://www.swamid.se/": {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions": None,  # All I have
                    "name_form": NAME_FORMAT_URI,
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    "entity_categories": ["swamid"],
                    "fail_on_missing_requested": False,  # Don't fail on unsatisfied RequiredAttributes
                },
            },
            "name_id_format": [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT],
        },
    },
    "debug": True,
    "metadata": {"local": [swamid_sp_metadata_path, coco_sp_metadata_path, esi_coco_sp_metadata_path]},
    # "attribute_map_dir": attrmaps_path,
    "key_file": key_path,
    "cert_file": cert_path,
    "xmlsec_binary": xmlsec_path,
    "organization": {
        "display_name": "eduID UNITTEST",
        "name": "eduID UNITTEST",
        "url": "http://www.eduid.se/",
    },
}


# SP config
def get_sp_config(sp_base: str) -> dict:
    """
    Use this to change SP_BASE in config
    """
    sp_base_config = {
        # your entity id, usually your subdomain plus the url to the metadata view
        "entityid": f"{sp_base}/metadata/",
        # this block states what services we provide
        "service": {
            # we are just a lonely SP
            "sp": {
                "name": "Eduid Dashboard SP",
                "endpoints": {
                    # url and binding to the assertion consumer service view
                    # do not change the binding or service name
                    "assertion_consumer_service": [
                        (f"{sp_base}/acs/", BINDING_HTTP_POST),
                        ("https://localhost:8080/acs/", BINDING_HTTP_POST),
                    ],
                    # url and binding to the single logout service view
                    # do not change the binding or service name
                    "single_logout_service": [(f"{sp_base}/ls/", BINDING_HTTP_REDIRECT)],
                },
                # in this section the list of IdPs we talk to are defined
                "idp": {
                    # we do not need a WAYF service since there is
                    # only an IdP defined here. This IdP should be
                    # present in our metadata
                    # the keys of this dictionary are entity ids
                    f"{IDP_BASE}/idp.xml": {
                        "single_sign_on_service": {BINDING_HTTP_REDIRECT: f"{IDP_BASE}/sso/redirect"},
                        "single_logout_service": {BINDING_HTTP_REDIRECT: f"{IDP_BASE}/slo/redirect"},
                    },
                },
            },
        },
        "debug": True,
        "metadata": {"local": [idp_metadata_path]},
        "key_file": key_path,
        "cert_file": cert_path,
        "xmlsec_binary": xmlsec_path,
        "organization": {
            "display_name": "eduID UNITTEST SP",
            "name": "eduID UNITTEST SP",
            "url": "https://www.eduid.se/",
        },
    }
    return sp_base_config


SP_CONFIG = get_sp_config("https://sp.example.edu/saml2")
UNKNOWN_SP_CONFIG = get_sp_config("https://unknown-sp.example.org/foo")
COCO_SP_CONFIG = get_sp_config("https://coco.example.edu/saml2")
ESI_COCO_SP_CONFIG = get_sp_config("https://esi-coco.example.edu/saml2")
