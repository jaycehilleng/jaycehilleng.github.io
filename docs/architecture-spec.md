Markdown
# Reference Architecture: Secure Model Context Protocol (MCP) Execution Runtime

**Author:** Jayce Hill | Principal AI Security Architect  
**Target Domain:** Agentic AI Security, Non-Human Identity (NHI) Governance, Zero-Trust Sandboxing  

---

## Executive Overview
When enterprise AI agents invoke external tools via the **Model Context Protocol (MCP)**, traditional network 
and IAM perimeters fail. Agents are vulnerable to **Indirect Prompt Injection (XPIA)**, **Excessive Agency**, 
and **Confused Deputy** attacks.

This reference architecture implements a **Dual-Trust Boundary Architecture** that decouples identity 
delegation from tool execution:
1. **Control Plane (Identity):** Uses **Entra Agent IDs** / Workload Identity Federation with short-lived, 
Proof-of-Possession (PoP) scoped OAuth tokens.
2. **Data & Execution Plane (Sandboxing):** Intercepts JSON-RPC tool calls via an **Out-of-Band MCP Security 
Proxy** before executing tools inside an isolated, containerized micro-sandbox.

---

## Interactive End-to-End Sequence Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Enterprise User
    participant Agent as 🤖 Agentic Engine (LLM)
    participant Entra as 🔑 Entra ID / IdP
    participant Proxy as 🛡️ Out-of-Band Security Proxy
    participant Sandbox as 📦 Ephemeral Sandbox (ACA/gVisor)
    participant Target as 💾 Internal Target (DB / API)

    User->>Agent: "Fetch customer report and process refund"
    Agent->>Entra: Request Scoped Token (Entra Agent ID)
    Entra-->>Agent: Issue Short-Lived PoP Token (TTL <= 15m)
    Agent->>Proxy: Submit MCP Tool Call (JSON-RPC)
    
    rect rgb(240, 240, 240)
        note over Proxy: Inspection & Validation Phase
        Proxy->>Proxy: 1. Scan for Shell/SQL Injection Patterns
        Proxy->>Proxy: 2. Evaluate Policy via OPA (RBAC Matrix)
        Proxy->>Proxy: 3. Sanitize Payload & Strip PII
    end

    alt Policy Denied or Injection Detected
        Proxy-->>Agent: ❌ 403 Forbidden / Security Violation
    else Policy Approved
        Proxy->>Sandbox: Execute Tool Payload (mTLS)
        Sandbox->>Target: Query Database via Scoped Micro-Token
        Target-->>Sandbox: Return Raw Data
        Sandbox-->>Proxy: Return Result Payload
        Proxy-->>Agent: Return Sanitized Context
        Agent-->>User: Present Final Answer
    end

Technical Component Architecture
1. Identity Delegation & Non-Human Identity (NHI)
Identity Principal: Every autonomous agent is provisioned an Entra Agent ID (Service Principal).

Token Exchange: Agents exchange credentials for short-lived, single-use OAuth 2.0 tokens bound to specific 
tool scopes.

Least Privilege: Downstream databases receive micro-tokens with read-only scopes, preventing lateral movement 
if an agent is compromised.

2. Out-of-Band MCP Inspection Proxy
Protocol Support: Native JSON-RPC 2.0 parsing for MCP tools/call methods.

Deterministic Policy Engine: Integrates Open Policy Agent (OPA) sidecars to evaluate role-based tool 
execution rules.

Payload Inspection: Regex and semantic evaluation detecting prompt hijacking (IGNORE PREVIOUS INSTRUCTIONS), 
command injection, and data exfiltration vectors.

3. Ephemeral Sandbox Container
Runtime Isolation: Containerized execution using Azure Container Apps (ACA) / gVisor sandboxes with read-only 
root filesystems.

Egress Control: Strict Deny-All egress firewall rules. Outbound traffic is restricted exclusively to 
authorized enterprise API endpoints.
