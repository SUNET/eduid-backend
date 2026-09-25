from os import path

import saml2
from saml2 import attributemaps

if attributemaps.__file__ is None:
    raise RuntimeError("Cannot determine attributemaps directory")

DEFAULT_ATTRIBUTEMAPS = path.dirname(attributemaps.__file__)

BASE_URL = "http://test.localhost:6544/"
SAML2DIR = path.dirname(__file__)

SAML_CONFIG = {
    # full path to the xmlsec1 binary programm
    "xmlsec_binary": "/usr/bin/xmlsec1",
    # your entity id, usually your subdomain plus the url to the metadata view
    "entityid": f"{BASE_URL}saml2-metadata",
    # directory with attribute mapping
    "attribute_map_dir": DEFAULT_ATTRIBUTEMAPS,
    # this block states what services we provide
    "service": {
        # we are just a lonely SP
        "sp": {
            "name": "EduID Example SP",
            "endpoints": {
                # url and binding to the assetion consumer service view
                # do not change the binding or service name
                "assertion_consumer_service": [
                    (f"{BASE_URL}saml2-acs", saml2.BINDING_HTTP_POST),
                ],
                # url and binding to the single logout service view
                # do not change the binding or service name
                "single_logout_service": [
                    (f"{BASE_URL}saml2-ls", saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            # Do not check for signature during tests
            "want_response_signed": False,
            # The test IdP's metadata has no signing certificate (see
            # remote_metadata.xml), so there is no private key to sign test
            # LogoutRequests with either. Development-only opt-in, mirrored in
            # pygamlastan's compat shim.
            # TODO(pygamlastan migration): this opt-in only proves the bypass
            # exists, not that real signature verification works. Once
            # pygamlastan is an actual dependency (not just spiked in a venv),
            # add a dedicated test that generates a real test-IdP keypair,
            # publishes its cert in remote_metadata.xml, and signs a
            # LogoutRequest with saml2.sigver.CryptoBackendXmlSec1.sign_statement()
            # - asserting both that a validly-signed request is accepted and
            # that an invalid/missing one is still rejected. Do not bolt
            # signing onto the shared logout_request() fixture for that; keep
            # it a separate test so this unsigned-bypass path stays covered too.
            "allow_unsigned_logout_requests": True,
            # in this section the list of IdPs we talk to are defined
            "idp": {
                # we do not need a WAYF service since there is
                # only an IdP defined here. This IdP should be
                # present in our metadata
                # the keys of this dictionary are entity ids
                "https://idp.example.com/simplesaml/saml2/idp/metadata.php": {
                    "single_sign_on_service": {
                        saml2.BINDING_HTTP_REDIRECT: "https://idp.example.com/simplesaml/saml2/idp/SSOService.php",
                    },
                    "single_logout_service": {
                        saml2.BINDING_HTTP_REDIRECT: "https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php",
                    },
                },
            },
        },
    },
    # where the remote metadata is stored
    "metadata": {
        "local": [path.join(SAML2DIR, "remote_metadata.xml")],
    },
    # set to 1 to output debugging information
    "debug": 1,
    # certificate
    "key_file": path.join("{}{}".format(SAML2DIR, "/certs"), "server.key"),  # private part
    "cert_file": path.join("{}{}".format(SAML2DIR, "/certs"), "server.crt"),  # public part
    # own metadata settings
    "contact_person": [
        {
            "given_name": "Sysadmin",
            "sur_name": "",
            "company": "Example CO",
            "email_address": "sysadmin@example.com",
            "contact_type": "technical",
        },
        {
            "given_name": "Admin",
            "sur_name": "CEO",
            "company": "Example CO",
            "email_address": "admin@example.com",
            "contact_type": "administrative",
        },
    ],
    # you can set multilanguage information here
    "organization": {
        "name": [("Example CO", "es"), ("Example CO", "en")],
        "display_name": [("Example", "es"), ("Example", "en")],
        "url": [("http://www.example.com", "es"), ("http://www.example.com", "en")],
    },
}
