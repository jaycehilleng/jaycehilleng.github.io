"""
Non-Human Identity (NHI) Proof-of-Possession (PoP) Token Validator
Validates short-lived OAuth 2.0 JWTs, cnf confirmation claims, and agent execution scopes.
"""

import time
from typing import Any, Dict


class TokenValidationError(Exception):
    """Custom exception raised when JWT validation fails."""
    pass


class PoPTokenValidator:
    def __init__(self, expected_audience: str, max_ttl_seconds: int = 900):
        self.expected_audience = expected_audience
        self.max_ttl_seconds = max_ttl_seconds  # Default 15 minutes max TTL

    def validate_token_claims(self, claims: Dict[str, Any], required_scope: str) -> bool:
        """
        Validates JWT claims against Zero-Trust Non-Human Identity standards.
        """
        now = int(time.time())

        # 1. Expiration & NBF Checks
        exp = claims.get("exp", 0)
        nbf = claims.get("nbf", 0)
        iat = claims.get("iat", 0)

        if now >= exp:
            raise TokenValidationError("Token Security Error: Token has expired.")

        if now < nbf:
            raise TokenValidationError("Token Security Error: Token not active yet (nbf violation).")

        # 2. Maximum TTL Enforcement (15 Minutes)
        if (exp - iat) > self.max_ttl_seconds:
            raise TokenValidationError(
                f"Token Security Error: TTL exceeds maximum allowed lifespan of {self.max_ttl_seconds} seconds."
            )

        # 3. Audience Validation
        aud = claims.get("aud")
        if aud != self.expected_audience:
            raise TokenValidationError(f"Token Security Error: Invalid audience '{aud}'. Expected '{self.expected_audience}'.")

        # 4. Proof-of-Possession (cnf) Claim Check
        cnf = claims.get("cnf")
        if not cnf or "jwk" not in cnf:
            raise TokenValidationError("Token Security Error: Missing required Proof-of-Possession (cnf) confirmation claim.")

        # 5. Fine-Grained Scope Verification
        scopes = claims.get("scp", "").split()
        if required_scope not in scopes:
            raise TokenValidationError(f"Token Security Error: Missing required scope '{required_scope}'. Granted: {scopes}")

        return True