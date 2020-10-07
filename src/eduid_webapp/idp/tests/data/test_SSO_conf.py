import os

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

_hostname = 'unittest-idp.example.edu'
IDP_BASE = "https://{!s}".format(_hostname)

here = os.path.dirname(__file__)
key_path = os.path.join(here, 'idp-public-snakeoil.key')
cert_path = os.path.join(here, 'idp-public-snakeoil.pem')

# attrmaps_path = os.path.join(here, '../../../attributemaps')
idp_metadata_path = os.path.join(here, 'idp_metadata.xml')
sp_metadata_path = os.path.join(here, 'sp_metadata.xml')

# IdP config
CONFIG = {
    "entityid": f'{IDP_BASE}/idp.xml',
    "description": "eduID UNITTEST identity provider",
    "service": {
        "idp": {
            "name": "eduID UNITTEST IdP",
            "scope": ["eduid.example.edu"],
            "endpoints": {
                "single_sign_on_service": [
                    (f'{IDP_BASE}/sso/redirect', BINDING_HTTP_REDIRECT),
                    (f'{IDP_BASE}/sso/post', BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    (f'{IDP_BASE}/slo/soap', BINDING_SOAP),
                    (f'{IDP_BASE}/slo/post', BINDING_HTTP_POST),
                    (f'{IDP_BASE}/slo/redirect', BINDING_HTTP_REDIRECT),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 5},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    # "entity_categories": ["swamid", "edugain"]
                    "entity_categories": [],
                },
            },
            "name_id_format": [NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_PERSISTENT],
        },
    },
    "debug": True,
    "metadata": {"local": [sp_metadata_path]},
    # "attribute_map_dir": attrmaps_path,
    "key_file": key_path,
    "cert_file": cert_path,
    "xmlsec_binary": xmlsec_path,
    "organization": {"display_name": "eduID UNITTEST", "name": "eduID UNITTEST", "url": "http://www.eduid.se/",},
}


# SP config
SP_BASE = 'https://sp.example.edu/saml2'

SP_CONFIG = {
    # your entity id, usually your subdomain plus the url to the metadata view
    'entityid': f'{SP_BASE}/metadata/',  # f'{SP_BASE}/sp.xml',
    # this block states what services we provide
    'service': {
        # we are just a lonely SP
        'sp': {
            'name': 'Eduid Dashboard SP',
            'endpoints': {
                # url and binding to the assertion consumer service view
                # do not change the binding or service name
                'assertion_consumer_service': [(f'{SP_BASE}/acs/', BINDING_HTTP_POST),],
                # url and binding to the single logout service view
                # do not change the binding or service name
                'single_logout_service': [(f'{SP_BASE}/ls/', BINDING_HTTP_REDIRECT),],
            },
            # in this section the list of IdPs we talk to are defined
            'idp': {
                # we do not need a WAYF service since there is
                # only an IdP defined here. This IdP should be
                # present in our metadata
                # the keys of this dictionary are entity ids
                f'{IDP_BASE}/idp.xml': {
                    'single_sign_on_service': {BINDING_HTTP_REDIRECT: f'{IDP_BASE}/sso/redirect',},
                    'single_logout_service': {BINDING_HTTP_REDIRECT: f'{IDP_BASE}/slo/redirect',},
                },
            },
        },
    },
    "debug": True,
    "metadata": {"local": [idp_metadata_path]},
    "key_file": key_path,
    "cert_file": cert_path,
    "xmlsec_binary": xmlsec_path,
    "organization": {"display_name": "eduID UNITTEST SP", "name": "eduID UNITTEST SP", "url": "http://www.eduid.se/",},
}

UNKNOWN_SP_CONFIG = dict(SP_CONFIG)
UNKNOWN_SP_CONFIG['entityid'] = 'https://unknown-sp.example.org/foo'
