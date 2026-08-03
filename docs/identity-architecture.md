# Architectural Spec: Non-Human Identity (NHI) Governance & Proof-of-Possession Tokens

## Executive Overview

In autonomous agentic workflows, traditional long-lived API keys and static service principal credentials present severe security risks, including identity hijacking, confused deputy exploits, and excessive agency. 

This specification defines a **Dual-Trust Identity Architecture** using **Microsoft Entra Agent IDs** and **Workload Identity Federation**. By enforcing short-lived Proof-of-Possession (PoP) OAuth 2.0 tokens bound to specific agent execution sessions, we establish cryptographically verifiable non-human identity (NHI) boundaries for every tool invocation.

---

## Identity Boundary Architecture

┌────────────────────────┐      1. Exchange Workload Assertion     ┌────────────────────────┐
│  Agent Execution Scope │ ──────────────────────────────────────> │   Microsoft Entra ID   │
│  (Ephemeral ACA Task)  │ <────────────────────────────────────── │  (Agent ID Provider)   │
└───────────┬────────────┘      2. Issue Short-Lived PoP Token     └────────────────────────┘
│                      (TTL <= 15 minutes, Bound cnf)
│
│ 3. Submit MCP Request + Bearer PoP Token
▼
┌────────────────────────┐
│   APIM AI Gateway      │
│ (iac/azure/apim-policy)│
└───────────┬────────────┘
│
│ 4. Forward to Identity Sidecar
▼
┌────────────────────────┐
│  PoP Token Validator   │ ──> Validates Token Expiry, Signature, Audience,
│(src/identity/validator)│     and Session Confirmation (cnf) Claim
└───────────┬────────────┘
│
│ 5. Validated Request
▼
┌────────────────────────┐
│ Zero-Trust MCP Proxy   │
│ (src/mcp_proxy/proxy)  │
└────────────────────────┘


---

## Key Identity Controls

| Control Layer | Implementation Pattern | Security Property |
| :--- | :--- | :--- |
| **Identity Delegation** | Microsoft Entra Agent ID + Workload Identity | Eliminates hardcoded client secrets; authenticates agent tasks via OIDC assertions. |
| **Token Binding** | OAuth 2.0 Proof-of-Possession (`cnf` claim) | Prevents token replay if a Bearer token is intercepted in transit or logged. |
| **Temporal Scoping** | Max TTL $\le 15$ Minutes | Constrains token lifespan to the active execution context of the agent task. |
| **Least Privilege** | Fine-Grained OAuth Scopes (`Tool.Execute.<Name>`) | Ensures agents only hold permissions required for the targeted tool invocation. |

---

## Threat Mitigation Matrix

* **Confused Deputy:** A compromised lower-privilege agent cannot use its token to invoke higher-tier administrative tools because tokens are scoped to explicit tool identities.
* **Token Exfiltration / Replay:** Intercepted tokens fail validation at the sidecar if the client cannot prove possession of the private key bound in the `cnf` claim.
* **Excessive Agency:** Automated scope downgrades dynamically restrict permissions based on the active task execution state.