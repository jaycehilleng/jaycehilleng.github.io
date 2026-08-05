# Architectural Spec: Non-Human Identity (NHI) Governance & Proof-of-Possession Tokens

## Executive Overview

In autonomous agentic workflows, traditional long-lived API keys and static service principal credentials present severe security risks, including identity hijacking, confused deputy exploits, and excessive agency.

This specification defines a **Dual-Trust Identity Architecture** using **Microsoft Entra Agent IDs** and **Workload Identity Federation**. By enforcing short-lived Proof-of-Possession (PoP) OAuth 2.0 tokens bound to specific agent execution sessions, we establish cryptographically verifiable non-human identity (NHI) boundaries for every tool invocation.

---

## Identity Boundary Architecture

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Ephemeral ACA Task<br/>(Agent Execution Scope)
    participant Entra as Microsoft Entra ID<br/>(Agent ID Provider)
    participant APIM as APIM AI Gateway<br/>(iac/azure/apim-policy)
    participant Sidecar as PoP Token Validator<br/>(src/identity/token_validator.py)
    participant Proxy as Zero-Trust MCP Proxy<br/>(src/mcp_proxy/proxy.py)

    Agent->>Entra: 1. Exchange Workload Assertion
    Entra-->>Agent: 2. Issue Short-Lived PoP Token (TTL <= 15 mins, Bound cnf)
    Agent->>APIM: 3. Submit MCP Request + Bearer PoP Token
    APIM->>Sidecar: 4. Forward to Identity Sidecar
    Note over Sidecar: Validates Token Expiry, Signature,<br/>Audience, & Session Confirmation (cnf) Claim
    Sidecar->>Proxy: 5. Forward Validated Request