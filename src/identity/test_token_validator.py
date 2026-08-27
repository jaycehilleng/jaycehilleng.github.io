"""
Unit tests for PoP Token Validator (Proof-of-Possession and RFC 7800 cnf claim validation).
"""

import time
import unittest

try:
    from src.identity.token_validator import PoPTokenValidator, TokenValidationError
except ImportError:
    from token_validator import PoPTokenValidator, TokenValidationError


class TestPoPTokenValidator(unittest.TestCase):
    def setUp(self):
        self.expected_aud = "https://mcp.internal.identity"
        self.validator = PoPTokenValidator(expected_audience=self.expected_aud, max_ttl_seconds=900)
        self.required_scope = "telemetry:read"

    def test_valid_pop_token(self):
        now = int(time.time())
        token = {
            "sub": "agent-007",
            "aud": self.expected_aud,
            "scp": "telemetry:read admin:access",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "cnf": {"jwk": {"kty": "EC", "crv": "P-256"}}
        }
        self.assertTrue(self.validator.validate_token_claims(token, self.required_scope))

    def test_missing_cnf_claim(self):
        now = int(time.time())
        token = {
            "sub": "agent-007",
            "aud": self.expected_aud,
            "scp": "telemetry:read",
            "iat": now,
            "nbf": now,
            "exp": now + 300
        }
        with self.assertRaises(TokenValidationError):
            self.validator.validate_token_claims(token, self.required_scope)

    def test_expired_token(self):
        now = int(time.time())
        token = {
            "sub": "agent-007",
            "aud": self.expected_aud,
            "scp": "telemetry:read",
            "iat": now - 600,
            "nbf": now - 600,
            "exp": now - 60,
            "cnf": {"jwk": {"kty": "EC"}}
        }
        with self.assertRaises(TokenValidationError):
            self.validator.validate_token_claims(token, self.required_scope)

    def test_ttl_exceeds_max(self):
        now = int(time.time())
        token = {
            "sub": "agent-007",
            "aud": self.expected_aud,
            "scp": "telemetry:read",
            "iat": now,
            "nbf": now,
            "exp": now + 7200,
            "cnf": {"jwk": {"kty": "EC"}}
        }
        with self.assertRaises(TokenValidationError):
            self.validator.validate_token_claims(token, self.required_scope)

    def test_missing_required_scope(self):
        now = int(time.time())
        token = {
            "sub": "agent-007",
            "aud": self.expected_aud,
            "scp": "reports:read",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "cnf": {"jwk": {"kty": "EC"}}
        }
        with self.assertRaises(TokenValidationError):
            self.validator.validate_token_claims(token, self.required_scope)


if __name__ == "__main__":
    unittest.main()