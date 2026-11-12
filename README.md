# Cloud Infrastructure & Agentic Security Engineering

[![CI Security Test Suite](https://github.com/jaycehilleng/jaycehilleng.github.io/actions/workflows/ci.yml/badge.svg)](https://github.com/jaycehilleng/jaycehilleng.github.io/actions/workflows/ci.yml)

> **Start here — Secure MCP Execution Runtime:** proxy code in [`src/mcp_proxy/`](./src/mcp_proxy/), identity and policy in [`src/identity/`](./src/identity/), infrastructure in [`iac/azure/`](./iac/azure/), threat matrix in [`docs/threat-matrix.md`](./docs/threat-matrix.md). Run the tests in one command (see [Verify it yourself](#-verify-it-yourself)).

Welcome to my principal-level engineering workspace and public security research lab. This repository houses technical architecture specs, security audits, and hands-on laboratory implementations focused on **Zero-Trust Agent Sandboxing**, **Model Context Protocol (MCP) Governance**, and **Cloud Infrastructure Hardening**.

---
### Architecture & Security Governance Highlights
- **Agentic AI Defense:** Hardened Model Context Protocol (MCP) proxy with recursive parameter sanitization and runtime boundary isolation.
- **Enterprise IAM & Trust:** RFC 7800 Proof-of-Possession token validation, least-privilege App-to-App (A2A) authorization, and decoupled Policy-Based Access Control (PBAC).
- **Policy-as-Code (PaC):** Declarative OPA/Rego default-deny policy ([`src/identity/policies/mcp_tool_policy.rego`](./src/identity/policies/mcp_tool_policy.rego)) decoupling authorization from execution runtimes.
- **Threat Modeling & Auditability:** Formal STRIDE threat mitigation matrix, 3-tier Trust Boundary architecture, and SIEM/APM telemetry integration for banking-grade traceability.

---


## 🎯 Active Strategic Focus: Agentic AI Governance

As enterprise AI adoption shifts from building isolated agents to governing how they interact with internal enterprise tools and data, centralized control planes are critical. 

This workspace evaluates, audits, and extends enterprise reference architectures (such as **Microsoft's AI-Gateway & Foundry Toolbox** and **Google/Mandiant AI Security Frameworks**) to address critical security gaps in production deployments:

* **Indirect Prompt Injection Mitigation:** Inspecting untrusted data payloads returned by MCP tools before re-entry into agent context.
* **Execution Boundary Sandboxing:** Hardening tool execution environments using container-level isolation (gVisor / Wasm / Ephemeral Runtimes).
* **Zero-Trust Policy Enforcement:** Implementing fine-grained Open Policy Agent (OPA) sidecars and custom API Management (APIM) inspection proxies.

---

## 🏗️ Laboratory & Architecture Portfolio

| Project / Module | Focus Area | Tech Stack | Status |
| :--- | :--- | :--- | :--- |
| [MCP Security Proxy](./src/mcp_proxy/) | `SecureMCPProxy`: policy enforcement point for MCP tool calls — JSON-RPC 2.0 validation, signature-verified caller identity, tool-level RBAC, recursive argument sanitization (CWE-88, path traversal, command chaining), structured security telemetry. Upstream forwarding to MCP servers is next. | Python, pytest | **Implemented · tests passing in CI** |
| [NHI Token Validator](./src/identity/) | `PoPTokenValidator`: ES256 JWT signature verification (explicit algorithm allow-list, rejects `alg: none`), audience, TTL, agent scopes, and RFC 7800 `cnf` key-binding claim. Per-request DPoP proof verification (RFC 9449) is next. | Python, PyJWT, pytest | **Implemented · tests passing in CI** |
| [Tool Authorization Policy](./src/identity/policies/mcp_tool_policy.rego) | Default-deny OPA/Rego policy: PoP-validated caller, scope-gated read tools, elevated scope + tenant match for write tools. | OPA / Rego | **Implemented** (policy authored; OPA sidecar wiring is next) |
| [Azure Control Plane IaC](./iac/azure/) | Entra Agent ID identity, APIM inspection policy, and KQL audit queries for the runtime. | Azure Bicep, APIM, KQL | **Implemented** |
| [AI Gateway Audit Spec](./docs/architecture-spec.md) | Technical critique and zero-trust extension design for central AI control planes. | Azure Bicep, APIM Policies, MCP | **Complete** |
| Execution Sandboxing | Isolating tool execution in ephemeral, kernel-isolated runtimes (gVisor / Wasm). | gVisor, containers | **Designed** (architecture spec; implementation on roadmap) |

---

## ✅ Verify it yourself

```bash
git clone https://github.com/jaycehilleng/jaycehilleng.github.io
cd jaycehilleng.github.io
pip install -r requirements.txt
PYTHONPATH=. python -m pytest src -v
```

The suite includes integration tests that run the proxy against the real validator with signed tokens: wrong-key, tampered-payload, and `alg: none` tokens are all blocked. The same suite runs on every push via GitHub Actions ([CI workflow](./.github/workflows/ci.yml)), alongside CodeQL static analysis ([CodeQL workflow](./.github/workflows/codeql.yml)).

---

## 🛠️ Repository Organization

```text
.
├── docs/               --> Architectural specs, security audits, and technical writeups
├── iac/                --> Infrastructure-as-code (Azure Bicep, APIM policies)
└── src/                --> MCP security proxy validator, identity token validation, & Python sources