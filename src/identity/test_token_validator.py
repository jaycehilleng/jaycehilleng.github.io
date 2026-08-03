"""
Unit Tests for PoPTokenValidator
Validates token expiration, TTL thresholds, cnf proof-of-possession claims, and audience/scope matching.
"""

import time
import pytest
from token_validator import PoPTokenValidator, TokenValidationError


@pytest.fixture
def validator():
    return PoPTokenValidator(expected_audience="https://api.hillsecadvisors.com/mcp", max_ttl_seconds=900)


def test_valid_pop_token_claims(validator):
    now = int(time.time())
    valid_claims = {
        "aud": "https://api.hillsecadvisors.com/mcp",
        "iat": now,
        "nbf": now,
        "exp": now + 600,  # 10 minute TTL
        "cnf": {"jwk": {"kty": "RSA", "e": "AQAB", "n": "sample-thumbprint"}},
        "scp": "Tool.Execute.QueryDatabase User.Read",
    }
    assert validator.validate_token_claims(valid_claims, required_scope="Tool.Execute.QueryDatabase") is True


def test_expired_token_rejection(validator):
    now = int(time.time())
    expired_claims = {
        "aud": "https://api.hillsecadvisors.com/mcp",
        "iat": now - 1000,
        "nbf": now - 1000,
        "exp": now - 100,
        "cnf": {"jwk": {"kty": "RSA"}},
        "scp": "Tool.Execute.QueryDatabase",
    }
    with pytest.raises(TokenValidationError) as exc_info:
        validator.validate_token_claims(expired_claims, required_scope="Tool.Execute.QueryDatabase")
    assert "Token has expired" in str(exc_info.value)


def test_excessive_ttl_rejection(validator):
    now = int(time.time())
    excessive_ttl_claims = {
        "aud": "https://api.hillsecadvisors.com/mcp",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,  # 1 hour TTL (Exceeds 15m threshold)
        "cnf": {"jwk": {"kty": "RSA"}},
        "scp": "Tool.Execute.QueryDatabase",
    }
    with pytest.raises(TokenValidationError) as exc_info:
        validator.validate_token_claims(excessive_ttl_claims, required_scope="Tool.Execute.QueryDatabase")
    assert "TTL exceeds maximum allowed lifespan" in str(exc_info.value)


def test_missing_cnf_claim_rejection(validator):
    now = int(time.time())
    missing_cnf_claims = {
        "aud": "https://api.hillsecadvisors.com/mcp",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "scp": "Tool.Execute.QueryDatabase",
    }
    with pytest.raises(TokenValidationError) as exc_info:
        validator.validate_token_claims(missing_cnf_claims, required_scope="Tool.Execute.QueryDatabase")
    assert "Missing required Proof-of-Possession (cnf)" in str(exc_info.value)


def test_insufficient_scope_rejection(validator):
    now = int(time.time())
    wrong_scope_claims = {
        "aud": "https://api.hillsecadvisors.com/mcp",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "cnf": {"jwk": {"kty": "RSA"}},
        "scp": "User.Read",
    }
    with pytest.raises(TokenValidationError) as exc_info:
        validator.validate_token_claims(wrong_scope_claims, required_scope="Tool.Execute.QueryDatabase")
    assert "Missing required scope" in str(exc_info.value)