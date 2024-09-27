import os
import unittest
from typing import Any

import simplejson as json

from eduid.vccs.client import VCCSClient, VCCSOathFactor, VCCSPasswordFactor, VCCSRevokeFactor

"""
Test VCCS client.
"""


class FakeVCCSClient(VCCSClient):
    """
    Sub-class of real VCCSClient overriding _execute_request_response()
    in order to fake HTTP communication.
    """

    def __init__(self, fake_response: str):
        self.fake_response = fake_response
        VCCSClient.__init__(self)

    def _execute_request_response(self, service: str, values: dict[str, Any]):
        self.last_service = service
        self.last_values = values
        return self.fake_response


class FakeVCCSPasswordFactor(VCCSPasswordFactor):
    """
    Sub-class that overrides the get_random_bytes function to make certain things testable.
    """

    def _get_random_bytes(self, num_bytes: int):
        b = os.urandom(1)
        if isinstance(b, str):
            # Python2
            return chr(0xA) * num_bytes
        # Python3
        return b"\x0a" * num_bytes


class TestVCCSClient(unittest.TestCase):
    def test_password_factor(self):
        """
        Test creating a VCCSPasswordFactor instance.
        """
        # XXX need to find test vectors created with another implementation!
        f = VCCSPasswordFactor("plaintext", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        self.assertEqual(
            f.to_dict("auth"),
            {
                "type": "password",
                "credential_id": "4711",
                "H1": "0b9ba6497c08106032a3337b",
            },
        )

    def test_utf8_password_factor(self):
        """
        Test creating a VCCSPasswordFactor instance.
        """
        # XXX need to find test vectors created with another implementation!
        f = VCCSPasswordFactor("plaintextåäöхэж", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        self.assertEqual(
            f.to_dict("auth"),
            {
                "type": "password",
                "credential_id": "4711",
                "H1": "bbcebc158aa37039e0fa3294",
            },
        )

    def test_OATH_factor_auth(self):
        """
        Test creating a VCCSOathFactor instance.
        """
        aead = "aa" * 20
        o = VCCSOathFactor("oath-hotp", 4712, nonce="010203040506", aead=aead, user_code="123456")
        self.assertEqual(
            o.to_dict("auth"),
            {
                "type": "oath-hotp",
                "credential_id": 4712,
                "user_code": "123456",
            },
        )

    def test_OATH_factor_add(self):
        """
        Test creating a VCCSOathFactor instance for an add_creds request.
        """
        aead = "aa" * 20
        o = VCCSOathFactor("oath-hotp", 4712, nonce="010203040506", aead=aead, key_handle=0x1234)
        self.assertEqual(
            o.to_dict("add_creds"),
            {
                "aead": aead,
                "credential_id": 4712,
                "digits": 6,
                "nonce": "010203040506",
                "oath_counter": 0,
                "type": "oath-hotp",
                "key_handle": 0x1234,
            },
        )

    def test_missing_parts_of_OATH_factor(self):
        """
        Test creating a VCCSOathFactor instance with missing parts.
        """
        aead = "aa" * 20
        o = VCCSOathFactor("oath-hotp", 4712, user_code="123456")
        # missing AEAD
        with self.assertRaises(ValueError):
            o.to_dict("add_creds")

        o = VCCSOathFactor("oath-hotp", 4712, nonce="010203040506", aead=aead, key_handle=0x1234, user_code="123456")
        # with AEAD o should be OK
        self.assertEqual(type(o.to_dict("add_creds")), dict)
        # unknown to_dict 'action' should raise
        with self.assertRaises(ValueError):
            o.to_dict("bad_action")

    def test_authenticate1(self):
        """
        Test parsing of successful authentication response.
        """
        resp = {
            "auth_response": {
                "version": 1,
                "authenticated": True,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor("password", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        self.assertTrue(c.authenticate("ft@example.net", [f]))

    def test_authenticate1_utf8(self):
        """
        Test parsing of successful authentication response with a password in UTF-8.
        """
        resp = {
            "auth_response": {
                "version": 1,
                "authenticated": True,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor("passwordåäöхэж", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        self.assertTrue(c.authenticate("ft@example.net", [f]))

    def test_authenticate2(self):
        """
        Test unknown response version
        """
        resp = {
            "auth_response": {
                "version": 999,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor("password", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        with self.assertRaises(AssertionError):
            c.authenticate("ft@example.net", [f])

    def test_authenticate2_utf8(self):
        """
        Test unknown response version with a password in UTF-8.
        """
        resp = {
            "auth_response": {
                "version": 999,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor("passwordåäöхэж", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        with self.assertRaises(AssertionError):
            c.authenticate("ft@example.net", [f])

    def test_add_creds1(self):
        """
        Test parsing of successful add_creds response.
        """
        credential_id = "4711"
        userid = "ft@example.net"
        password = "secret"
        resp = {
            "add_creds_response": {
                "version": 1,
                "success": True,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor(password, credential_id, "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        add_result = c.add_credentials(userid, [f])
        self.assertTrue(add_result)
        self.assertEqual(c.last_service, "add_creds")
        values = json.loads(c.last_values["request"])
        expected = {
            "add_creds": {
                "version": 1,
                "user_id": userid,
                "factors": [{"credential_id": credential_id, "H1": "6520c816376fd8ee6299ff31", "type": "password"}],
            }
        }
        self.assertEqual(expected, values)

    def test_add_creds1_utf8(self):
        """
        Test parsing of successful add_creds response with a password in UTF-8.
        """
        credential_id = "4711"
        userid = "ft@example.net"
        password = "passwordåäöхэж"
        resp = {
            "add_creds_response": {
                "version": 1,
                "success": True,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor(password, credential_id, "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        add_result = c.add_credentials(userid, [f])
        self.assertTrue(add_result)
        self.assertEqual(c.last_service, "add_creds")
        values = json.loads(c.last_values["request"])
        expected = {
            "add_creds": {
                "version": 1,
                "user_id": userid,
                "factors": [{"credential_id": credential_id, "H1": "80e6759a26bb9d439bc77d52", "type": "password"}],
            }
        }
        self.assertEqual(expected, values)

    def test_add_creds2(self):
        """
        Test parsing of unsuccessful add_creds response.
        """
        resp = {
            "add_creds_response": {
                "version": 1,
                "success": False,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor("password", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        self.assertFalse(c.add_credentials("ft@example.net", [f]))

    def test_add_creds2_utf8(self):
        """
        Test parsing of unsuccessful add_creds response with a password in UTF-8.
        """
        resp = {
            "add_creds_response": {
                "version": 1,
                "success": False,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        f = VCCSPasswordFactor("passwordåäöхэж", "4711", "$NDNv1H1$aaaaaaaaaaaaaaaa$12$32$")
        self.assertFalse(c.add_credentials("ft@example.net", [f]))

    def test_revoke_creds1(self):
        """
        Test parsing of unsuccessful revoke_creds response.
        """
        resp = {
            "revoke_creds_response": {
                "version": 1,
                "success": False,
            },
        }
        c = FakeVCCSClient(json.dumps(resp))
        r = VCCSRevokeFactor("4712", "testing revoke", "foobar")
        self.assertFalse(c.revoke_credentials("ft@example.net", [r]))

    def test_revoke_creds2(self):
        """
        Test revocation reason/reference bad types.
        """
        FakeVCCSClient(None)

        with self.assertRaises(TypeError):
            VCCSRevokeFactor(4712, 1234, "foobar")

        with self.assertRaises(TypeError):
            VCCSRevokeFactor(4712, "foobar", 2345)

    def test_unknown_salt_version(self):
        """Test unknown salt version"""
        with self.assertRaises(ValueError):
            VCCSPasswordFactor("anything", "4711", "$NDNvFOO$aaaaaaaaaaaaaaaa$12$32$")

    def test_generate_salt1(self):
        """Test salt generation."""
        f = VCCSPasswordFactor("anything", "4711")
        self.assertEqual(len(f.salt), 80)
        random, length, rounds = f._decode_parameters(f.salt)
        self.assertEqual(length, 32)
        self.assertEqual(rounds, 32)
        self.assertEqual(len(random), length)

    def test_generate_salt2(self):
        """Test salt generation with fake RNG."""

        f = FakeVCCSPasswordFactor("anything", "4711")
        self.assertEqual(len(f.salt), 80)
        random, length, rounds = f._decode_parameters(f.salt)
        self.assertEqual(length, 32)
        self.assertEqual(rounds, 32)
        self.assertEqual(len(random), length)
        self.assertEqual(f.salt, "$NDNv1H1$0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a$32$32$")
