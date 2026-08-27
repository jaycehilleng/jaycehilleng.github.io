# Architecture Specification & Threat Model: Zero-Trust Agentic Control Plane

## Executive Overview
As enterprise architectures adopt autonomous AI agents and tool-calling interfaces (e.g., Model Context Protocol / MCP), traditional perimeter-based security fails. Agents frequently act as **confused deputies**—executing untrusted input containing prompt injections, command expansions, or arbitrary parameter modifications.

This repository implements a production-grade, zero-dependency reference control plane providing:
1. **Cryptographic Non-Human Identity (NHI) Binding:** Short-lived RFC 7800 Proof-of-Possession (PoP) tokens utilizing `cnf` confirmation claims.
2. **Runtime Capability Isolation:** Deterministic Model Context Protocol (MCP) proxy sidecar enforcing Role-Based Access Control (RBAC) and schema whitelisting.
3. **Parameter & Argument Sanitization:** Recursive parameter inspection mitigating command chaining, path traversal, and CLI argument injection (e.g., CVE-2026-61459).
4. **Structured Security Telemetry:** Native, JSON-formatted audit events capturing latency, caller identity, tool execution status, and policy violation specifics for SIEM and Datadog APM ingestion.

---

## System Architecture & Trust Boundaries

[ Untrusted Execution Domain ]
            +------------------------------+
            |   User / LLM Prompt Engine   |
            +--------------+---------------+
                           |
                           | (1) Untrusted JSON-RPC Invocation
                           v
=+======
[ TRUST BOUNDARY 1: Identity & Ingress Security Gateway ]
|
+--------------v---------------+
|     PoP Token Validator      |
|  - RFC 7800 'cnf' Claim Check|
|  - Strict Max TTL (15m)      |
|  - Audience & Scope Binding  |
+--------------+---------------+
|
| (2) Verified Cryptographic Claims
v
=+======
[ TRUST BOUNDARY 2: Runtime Tool Isolation & Policy Enforcement ]
|
+--------------v---------------+
|       Secure MCP Proxy       |
|  - RBAC Policy Matrix        |
|  - Argument Injection Filter |
|  - Structured Telemetry Emitter
+--------------+---------------+
|
| (3) Sanitized & Authorized Execution
v
=+======
[ TRUST BOUNDARY 3: Core Enterprise Infrastructure & Data ]
|
+--------------v---------------+
|    Internal Tools & Data     |
| (Telemetry, Identity Graph)  |
+------------------------------+


---

## STRIDE Threat Model & Mitigations

| STRIDE Category | Specific Agent Threat Vector | Architectural Mitigation | Implementation Component |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Compromised bearer token replayed by malicious agent or rogue workload. | Mandate short-lived JWTs bound to ephemeral keys via RFC 7800 `cnf` (confirmation) claims; enforce strict audience checking. | `src/identity/token_validator.py` |
| **Tampering** | Tool parameters altered via indirect prompt injection (e.g., passing `--namespace=kube-system` or shell metachars). | Recursive regex parameter validation blocking CLI argument switches, null bytes, command substitution, and path traversal. | `src/mcp_proxy/proxy.py` (`_validate_arguments`) |
| **Repudiation** | Unaudited tool execution by autonomous non-human actors across microservices. | Structured JSON audit logging capturing timestamps, tool names, sub/caller_id, status (`ALLOWED`/`BLOCKED`), and latency. | `src/mcp_proxy/proxy.py` (`_emit_telemetry`) |
| **Information Disclosure** | Unauthorized agent accessing privileged identity graph or cluster telemetry. | Strict RBAC policy whitelist (`ALLOWED_TOOLS`) restricting tool execution to validated token roles. | `src/mcp_proxy/proxy.py` (`ALLOWED_TOOLS`) |
| **Denial of Service** | Long-lived token persistence or recursive malformed JSON-RPC payloads exhausting proxy memory. | Bounded token TTL enforcement ($\le 900\text{s}$) and deterministic JSON parse recovery returning standard error payloads. | `token_validator.py` & `proxy.py` |
| **Elevation of Privilege** | Confused deputy attack: Low-privilege agent invoking high-privilege tool methods. | Multi-tier validation: token scope verification followed by method-level RBAC policy evaluation before tool routing. | `PoPTokenValidator` + `SecureMCPProxy` |

---

## Telemetry Schema & SIEM / Observability Ingestion

All proxy decisions generate a standardized JSON audit record:

```json
{
  "timestamp": 1787859388.378,
  "event_type": "mcp_security_block",
  "tool_name": "read_telemetry",
  "status": "BLOCKED",
  "caller_id": "agent-service-account-01",
  "latency_ms": 0.379,
  "details": "Dangerous parameter pattern detected: 'cluster-1; cat /etc/passwd'"
}
