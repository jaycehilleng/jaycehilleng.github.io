"""
Secure MCP Proxy with Input Hardening, Argument Sanitization, and Structured Telemetry.
Zero external dependencies (uses standard library: json, re, logging, time).
"""

import json
import logging
import re
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("SecureMCPProxy")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class SecurityPolicyViolation(Exception):
    """Raised when an incoming MCP request violates security or policy constraints."""
    pass


class SecureMCPProxy:
    DANGEROUS_PATTERNS = [
        re.compile(r"[\x00\r\n]"),                  # Null bytes & CRLF injection
        re.compile(r"[;&|`$><]"),                   # Command chaining / shell execution
        re.compile(r"\.\./|\.\.\\"),                # Path traversal
        re.compile(r"^-{1,2}[a-zA-Z0-9]"),          # Leading dash argument flags (CVE-2026-61459)
    ]

    ALLOWED_TOOLS = {
        "read_telemetry": {"allowed_roles": ["appsec_auditor", "principal_architect"]},
        "query_identity_graph": {"allowed_roles": ["principal_architect"]},
    }

    def __init__(self, token_validator=None):
        self.token_validator = token_validator

    def _emit_telemetry(self, event_type: str, tool_name: Optional[str], status: str, caller_id: str, latency_ms: float, details: Optional[str] = None):
        """Emits structured JSON telemetry compatible with Datadog & SIEM ingestion."""
        telemetry_event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "tool_name": tool_name,
            "status": status,
            "caller_id": caller_id,
            "latency_ms": round(latency_ms, 3),
            "details": details,
        }
        logger.info(json.dumps(telemetry_event))

    def _validate_arguments(self, params: Any) -> None:
        """Recursively scans JSON-RPC parameters for injection vectors."""
        if isinstance(params, str):
            for pattern in self.DANGEROUS_PATTERNS:
                if pattern.search(params):
                    raise SecurityPolicyViolation(f"Dangerous parameter pattern detected: {params[:30]!r}")
        elif isinstance(params, dict):
            for key, value in params.items():
                self._validate_arguments(key)
                self._validate_arguments(value)
        elif isinstance(params, list):
            for item in params:
                self._validate_arguments(item)

    def handle_request(self, raw_json_rpc: str, auth_token: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        start_time = time.time()
        caller_id = auth_token.get("sub", "anonymous") if auth_token else "anonymous"
        tool_name = None
        payload = None

        try:
            try:
                payload = json.loads(raw_json_rpc)
            except (json.JSONDecodeError, TypeError) as exc:
                raise SecurityPolicyViolation(f"Invalid JSON payload: {str(exc)}")

            if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
                raise SecurityPolicyViolation("Malformed JSON-RPC 2.0 structure")

            tool_name = payload.get("method")
            req_id = payload.get("id")
            params = payload.get("params", {})

            # 1. Identity & Scope Validation
            if not auth_token or not self.token_validator:
                raise SecurityPolicyViolation("Missing or unverified authentication token")

            if not self.token_validator.validate_token(auth_token):
                raise SecurityPolicyViolation("Token failed cryptographic/TTL validation")

            # 2. RBAC Policy Evaluation
            if tool_name not in self.ALLOWED_TOOLS:
                raise SecurityPolicyViolation(f"Unauthorized or unknown tool: {tool_name}")

            caller_role = auth_token.get("role")
            if caller_role not in self.ALLOWED_TOOLS[tool_name]["allowed_roles"]:
                raise SecurityPolicyViolation(f"Caller role '{caller_role}' unauthorized for tool '{tool_name}'")

            # 3. Argument Injection & Parameter Sanitization
            self._validate_arguments(params)

            # Request Passed All Trust Boundaries
            latency_ms = (time.time() - start_time) * 1000
            self._emit_telemetry("mcp_tool_execution", tool_name, "ALLOWED", caller_id, latency_ms)

            return {
                "jsonrpc": "2.0",
                "result": {"status": "success", "executed_tool": tool_name},
                "id": req_id
            }

        except SecurityPolicyViolation as e:
            latency_ms = (time.time() - start_time) * 1000
            self._emit_telemetry("mcp_security_block", tool_name, "BLOCKED", caller_id, latency_ms, details=str(e))
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": str(e)},
                "id": payload.get("id") if isinstance(payload, dict) else None
            }