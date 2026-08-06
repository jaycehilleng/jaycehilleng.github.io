# Cloud Infrastructure & Agentic Security Engineering

Welcome to my principal-level engineering workspace and public security research lab. This repository houses technical architecture specs, security audits, and hands-on laboratory implementations focused on **Zero-Trust Agent Sandboxing**, **Model Context Protocol (MCP) Governance**, and **Cloud Infrastructure Hardening**.

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
| [MCP Security Proxy & Sandbox](./labs/mcp-security-proxy/) | Out-of-band payload inspection & runtime sandboxing for MCP tool calls. | Python, FastAPI, Docker, OPA, Azure APIM | **Active Build** |
| [AI Gateway Audit Spec](./docs/architecture/mcp-zero-trust-sandbox.md) | Technical critique and zero-trust extension design for central AI control planes. | Azure Bicep, APIM Policies, MCP | **Complete** |

---

## 🛠️ Repository Organization

```text

.
├── docs/               --> Architectural specs, security audits, and technical writeups
├── iac/                --> Infrastructure-as-code (Azure Bicep, APIM policies)
└── src/                --> MCP security proxy validator, identity token validation, & Python sources
