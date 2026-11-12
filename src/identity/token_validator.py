"""
Non-Human Identity (NHI) Proof-of-Possession (PoP) Token Validator
Validates short-lived OAuth 2.0 JWTs, cnf confirmation claims, and agent execution scopes.

Two entry points:
  * validate_token(token)        -- used by SecureMCPProxy. Accepts either a raw JWT
                                    (signature verified with the configured public key)
                                    or a claims dict that an upstream gateway (e.g. APIM
                                    validate-jwt) has already signature-verified.
  * validate_token_claims(...)   -- claims-level policy checks (TTL, audience, cnf, scope).

Scope note: the cnf check confirms the token is bound to a key (RFC 7800). Verifying a
per-request DPoP proof signed by that key (RFC 9449) is on the roadmap and is not
performed here.
"""

import time
from typing import Any, Dict, Optional, Sequence, Union

try:
    import jwt  # PyJWT
except ImportError:  # pragma: no cover - only hit when PyJWT is not installed
    jwt = None


class TokenValidationError(Exception):
    """Custom exception raised when JWT validation fails."""
    pass


class PoPTokenValidator:
    def __init__(
        self,
        expected_audience: str,
        max_ttl_seconds: int = 900,
        public_key: Optional[Any] = None,
        algorithms: Sequence[str] = ("ES256",),
        default_scope: Optional[str] = None,
    ):
        self.expected_audience = expected_audience
        self.max_ttl_seconds = max_ttl_seconds  # Default 15 minutes max TTL
        self.public_key = public_key
        self.algorithms = list(algorithms)
        self.default_scope = default_scope

    def verify_jwt(self, token: str) -> Dict[str, Any]:
        """Verifies the JWT signature, audience, exp and nbf, and returns its claims."""
        if jwt is None:
            raise TokenValidationError("PyJWT is required to verify signed tokens.")
        if self.public_key is None:
            raise TokenValidationError("No public key configured for signature verification.")
        try:
            return jwt.decode(
                token,
                key=self.public_key,
                algorithms=self.algorithms,  # explicit allow-list; rejects alg=none and alg confusion
                audience=self.expected_audience,
                options={"require": ["exp", "iat", "nbf", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenValidationError(f"Token Security Error: Signature or claim verification failed ({exc.__class__.__name__}).")

    def validate_token(self, token: Union[str, Dict[str, Any]], required_scope: Optional[str] = None) -> Dict[str, Any]:
        """
        Proxy-facing entry point. Returns the validated claims, or raises TokenValidationError.
        A str is treated as a raw JWT and signature-verified; a dict is treated as
        gateway-verified claims and receives claims-level checks only.
        """
        if isinstance(token, str):
            claims = self.verify_jwt(token)
        elif isinstance(token, dict):
            claims = token
        else:
            raise TokenValidationError("Token Security Error: Unsupported token type.")

        self.validate_token_claims(claims, required_scope or self.default_scope)
        return claims

    def validate_token_claims(self, claims: Dict[str, Any], required_scope: Optional[str]) -> bool:
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

        # 4. Proof-of-Possession (cnf) Key-Binding Claim Check (RFC 7800)
        cnf = claims.get("cnf")
        if not cnf or "jwk" not in cnf:
            raise TokenValidationError("Token Security Error: Missing required Proof-of-Possession (cnf) confirmation claim.")

        # 5. Fine-Grained Scope Verification
        if required_scope:
            scopes = claims.get("scp", "").split()
            if required_scope not in scopes:
                raise TokenValidationError(f"Token Security Error: Missing required scope '{required_scope}'. Granted: {scopes}")

        return True
