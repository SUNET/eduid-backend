#!/usr/bin/env python


"""
Example configuration for eduid-IdP.
"""

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = "/usr/bin/xmlsec1"


BASE = "http://localhost:8088"

CONFIG = {
    "entityid": f"{BASE}/idp.xml",
    "description": "My IDP",
    "service": {
        "aa": {
            "endpoints": {"attribute_service": [(f"{BASE}/attr", BINDING_SOAP)]},
            "name_id_format": [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT],
        },
        "aq": {
            "endpoints": {"authn_query_service": [(f"{BASE}/aqs", BINDING_SOAP)]},
        },
        "idp": {
            "name": "Rolands IdP",
            "endpoints": {
                "single_sign_on_service": [
                    (f"{BASE}/sso/redirect", BINDING_HTTP_REDIRECT),
                    (f"{BASE}/sso/post", BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    (f"{BASE}/slo/soap", BINDING_SOAP),
                    (f"{BASE}/slo/post", BINDING_HTTP_POST),
                    (f"{BASE}/slo/redirect", BINDING_HTTP_REDIRECT),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "entity_categories": ["swamid", "edugain"],
                },
            },
            "subject_data": "./idp.subject",
            "name_id_format": [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT],
        },
    },
    "debug": 1,
    "key_file": "pki/mykey.pem",
    "cert_file": "pki/mycert.pem",
    "metadata": {
        "local": ["/home/ft/work/NORDUnet/eduid-IdP/metadata.xml"],
    },
    "organization": {
        "display_name": "Rolands Identiteter",
        "name": "Rolands Identiteter",
        "url": "http://www.example.com",
    },
    "contact_person": [
        {
            "contact_type": "technical",
            "given_name": "Roland",
            "sur_name": "Hedberg",
            "email_address": "technical@example.com",
        },
        {"contact_type": "support", "given_name": "Support", "email_address": "support@example.com"},
    ],
    # This database holds the map between a subjects local identifier and
    # the identifier returned to a SP
    "xmlsec_binary": xmlsec_path,
    "attribute_map_dir": "../attributemaps",
    "logger": {
        "rotating": {
            "filename": "idp.log",
            "maxBytes": 500000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    },
}
