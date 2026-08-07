"""Unit Tests for Secure MCP Proxy."""

import pytest
from fastapi.testclient import TestClient
from src.mcp_proxy.proxy import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_inspect_clean_payload():
    payload = {"tool": "weather", "arguments": {"city": "Seattle"}}
    response = client.post("/inspect", json=payload)
    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_inspect_suspicious_payload():
    payload = {"tool": "shell", "arguments": {"command": "rm -rf /"}}
    response = client.post("/inspect", json=payload)
    assert response.status_code == 200
    assert response.json()["allowed"] is False