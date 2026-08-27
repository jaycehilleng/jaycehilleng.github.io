"""
Unit tests for SecureMCPProxy validation, RBAC, and parameter injection defense.
"""

import unittest
from unittest.mock import MagicMock
from src.mcp_proxy.proxy import SecureMCPProxy


class TestSecureMCPProxy(unittest.TestCase):
    def setUp(self):
        self.mock_validator = MagicMock()
        self.mock_validator.validate_token.return_value = True
        self.proxy = SecureMCPProxy(token_validator=self.mock_validator)
        self.valid_token = {
            "sub": "agent-service-account-01",
            "role": "principal_architect",
            "cnf": {"jwk": {"kty": "EC"}}
        }

    def test_authorized_tool_execution(self):
        req = '{"jsonrpc": "2.0", "method": "read_telemetry", "params": {"cluster_id": "us-east-1"}, "id": 1}'
        res = self.proxy.handle_request(req, auth_token=self.valid_token)
        self.assertIn("result", res)
        self.assertEqual(res["result"]["status"], "success")

    def test_rbac_denial_unauthorized_role(self):
        unauthorized_token = {"sub": "guest-agent", "role": "viewer", "cnf": {}}
        req = '{"jsonrpc": "2.0", "method": "query_identity_graph", "id": 2}'
        res = self.proxy.handle_request(req, auth_token=unauthorized_token)
        self.assertIn("error", res)
        self.assertIn("unauthorized", res["error"]["message"])

    def test_malformed_json_recovery(self):
        req = '{"jsonrpc": "2.0", "method": "read_telemetry", bad_json'
        res = self.proxy.handle_request(req, auth_token=self.valid_token)
        self.assertIn("error", res)
        self.assertIn("Invalid JSON", res["error"]["message"])

    def test_unregistered_tool_rejection(self):
        req = '{"jsonrpc": "2.0", "method": "execute_arbitrary_code", "id": 3}'
        res = self.proxy.handle_request(req, auth_token=self.valid_token)
        self.assertIn("error", res)
        self.assertIn("Unauthorized or unknown tool", res["error"]["message"])

    def test_argument_injection_leading_dash(self):
        """Mitigates CVE-2026-61459 style CLI argument injection via flags."""
        req = '{"jsonrpc": "2.0", "method": "read_telemetry", "params": {"resource_name": "--namespace=kube-system"}, "id": 4}'
        res = self.proxy.handle_request(req, auth_token=self.valid_token)
        self.assertIn("error", res)
        self.assertIn("Dangerous parameter pattern detected", res["error"]["message"])

    def test_argument_injection_command_chaining_and_traversal(self):
        """Mitigates command substitution, shell metacharacters, and path traversal."""
        payloads = [
            '{"target": "cluster-1; cat /etc/passwd"}',
            '{"path": "../../var/run/secrets"}',
            '{"query": "data`whoami`"}',
        ]
        for p in payloads:
            req = f'{{"jsonrpc": "2.0", "method": "read_telemetry", "params": {p}, "id": 5}}'
            res = self.proxy.handle_request(req, auth_token=self.valid_token)
            self.assertIn("error", res)
            self.assertIn("Dangerous parameter pattern detected", res["error"]["message"])


if __name__ == "__main__":
    unittest.main()