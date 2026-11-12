"""
Integration tests: SecureMCPProxy wired to the real PoPTokenValidator (no mocks).
Tokens are real ES256 JWTs signed with a key generated per test run.
"""

import json
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from src.identity.token_validator import PoPTokenValidator
from src.mcp_proxy.proxy import SecureMCPProxy

AUDIENCE = "https://mcp.internal.identity"


def _request(method="read_telemetry", params=None, req_id=1):
    return json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {"cluster_id": "us-east-1"}, "id": req_id})


class TestProxyWithRealValidator(unittest.TestCase):
    def setUp(self):
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.validator = PoPTokenValidator(
            expected_audience=AUDIENCE,
            public_key=self.signing_key.public_key(),
            algorithms=["ES256"],
            default_scope="agent:read",
        )
        self.proxy = SecureMCPProxy(token_validator=self.validator)

    def _claims(self, **overrides):
        now = int(time.time())
        claims = {
            "sub": "agent-service-account-01",
            "aud": AUDIENCE,
            "role": "principal_architect",
            "scp": "agent:read",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "cnf": {"jwk": {"kty": "EC", "crv": "P-256"}},
        }
        claims.update(overrides)
        return claims

    def _sign(self, claims, key=None):
        return jwt.encode(claims, key or self.signing_key, algorithm="ES256")

    def test_signed_token_is_allowed(self):
        res = self.proxy.handle_request(_request(), auth_token=self._sign(self._claims()))
        self.assertEqual(res["result"]["status"], "success")

    def test_token_signed_by_wrong_key_is_blocked(self):
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        res = self.proxy.handle_request(_request(), auth_token=self._sign(self._claims(), key=attacker_key))
        self.assertIn("error", res)
        self.assertIn("Token validation failed", res["error"]["message"])

    def test_tampered_payload_is_blocked(self):
        token = self._sign(self._claims(role="viewer"))
        header, payload, signature = token.split(".")
        forged_payload = jwt.utils.base64url_encode(
            json.dumps(self._claims(role="principal_architect")).encode()
        ).decode()
        res = self.proxy.handle_request(_request(), auth_token=f"{header}.{forged_payload}.{signature}")
        self.assertIn("error", res)

    def test_unsigned_alg_none_token_is_blocked(self):
        unsigned = jwt.encode(self._claims(), key=None, algorithm="none")
        res = self.proxy.handle_request(_request(), auth_token=unsigned)
        self.assertIn("error", res)

    def test_signed_token_without_cnf_is_blocked(self):
        claims = self._claims()
        del claims["cnf"]
        res = self.proxy.handle_request(_request(), auth_token=self._sign(claims))
        self.assertIn("Proof-of-Possession", res["error"]["message"])

    def test_signed_token_missing_scope_is_blocked(self):
        res = self.proxy.handle_request(_request(), auth_token=self._sign(self._claims(scp="reports:read")))
        self.assertIn("scope", res["error"]["message"])

    def test_rbac_uses_verified_claims(self):
        res = self.proxy.handle_request(
            _request(method="query_identity_graph"), auth_token=self._sign(self._claims(role="appsec_auditor"))
        )
        self.assertIn("unauthorized for tool", res["error"]["message"])

    def test_injection_blocked_after_valid_auth(self):
        res = self.proxy.handle_request(
            _request(params={"cluster_id": "us-east-1; rm -rf /"}), auth_token=self._sign(self._claims())
        )
        self.assertIn("Dangerous parameter pattern", res["error"]["message"])


if __name__ == "__main__":
    unittest.main()
