# Enterprise Threat Matrix: SAIF Alignment & OWASP Top 10 for LLM Applications

**Author:** Jayce Hill | Principal AI Security Architect  
**Framework Alignment:** Google Secure AI Framework (SAIF), OWASP Top 10 for LLM (2025/2026), NIST AI RMF  

---

## Executive Summary
Deploying autonomous agents and Model Context Protocol (MCP) tool integrations expands the attack surface beyond traditional application security boundaries. Threats such as **Indirect Prompt Injection (XPIA)**, **Data Exfiltration via Tool Misuse**, and **Non-Human Identity Hijacking** require structured threat modeling that maps real-world vectors directly to mitigation controls.

This matrix maps critical LLM vulnerabilities to SAIF risk domains and specifies concrete architectural controls implemented within the **Secure MCP Execution Runtime**.

---

## SAIF & OWASP Top 10 Threat Mapping

| Threat ID | OWASP Category | Vulnerability Description | SAIF Pillar Alignment | Runtime Mitigation Control |
| :--- | :--- | :--- | :--- | :--- |
| **TR-01** | **LLM01: Prompt Injection** | Direct or indirect prompt manipulation altering model intent and bypassing safety instructions. | **Expand Default Defenses** | Out-of-band regex & semantic payload inspection in `SecureMCPProxy`. |
| **TR-02** | **LLM02: Sensitive Info Disclosure** | System prompts, PII, or internal tool outputs leaked via agent context responses. | **Automate Defenses** | Output sanitization pipeline and strict PII stripping before returning tool outputs. |
| **TR-03** | **LLM06: Excessive Agency** | Agents granted overly broad tool access, leading to unauthorized actions. | **Incorporate Ecosystem Controls** | Entra Agent ID integration + OPA fine-grained capability matrix (RBAC). |
| **TR-04** | **LLM07: System Prompt Leakage** | Attackers craft prompts to reveal underlying system instructions or system state. | **Expand Default Defenses** | Strict contextual delimiter enforcement and prompt isolation boundaries. |
| **TR-05** | **LLM08: Vector & Extension Spoofing** | Compromised MCP tool extensions or poisoned vector embeddings inducing harmful tool calls. | **Secure Ecosystem** | Ephemeral, isolated Azure Container Apps execution sandboxes with read-only filesystems. |
| **TR-06** | **LLM09: Misconfiguration / NHI Risk** | Over-privileged service principals or static API tokens used for agent identity. | **Adapt Protections** | Short-lived OAuth 2.0 Proof-of-Possession (PoP) tokens bound to agent runtime context. |

---

## Architectural Control Mapping

### 1. Indirect Prompt Injection (XPIA) Defense Strategy
* **Threat Vector:** Untrusted data retrieved from external sources (e.g., database queries or user inputs) contains embedded instruction overrides like `IGNORE PREVIOUS INSTRUCTIONS`.
* **Control Layer:** The `SecureMCPProxy` acts as a deterministic barrier, evaluating all incoming `tools/call` JSON-RPC arguments before passing the payload to execution handlers.
* **Verification:** Unit tests within `src/mcp_proxy/proxy.py` validate immediate rejection (`status: REJECTED`) upon detecting signature patterns.

### 2. Non-Human Identity (NHI) Governance
* **Threat Vector:** Compromised agent tokens allow malicious actors to move laterally across enterprise cloud infrastructure.
* **Control Layer:** Every agent identity is assigned an **Entra Agent ID** with access tokens restricted to a maximum TTL of 15 minutes. Downstream tools receive micro-tokens constrained strictly to read-only capabilities.

### 3. Containerized Runtime Sandboxing
* **Threat Vector:** Malicious code execution or remote code execution (RCE) via arbitrary tool invocation.
* **Control Layer:** Tool execution runs inside ephemeral Azure Container Apps (ACA) sandboxes equipped with read-only root filesystems, scale-to-zero lifecycle policies, and restricted outbound network rules.

---

## Threat Matrix Verification & Audit Trail

All control implementations documented in this matrix are backed by reproducible code artifacts within this repository:
1. **Architecture Spec & Sequence Flow:** `docs/architecture-spec.md`
2. **Security Proxy Implementation:** `src/mcp_proxy/proxy.py`
3. **Infrastructure Declaration:** `iac/azure/main.bicep`
