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

```mermaid
graph TD
    subgraph UED["Untrusted Execution Domain"]
        UserEngine["User / LLM Prompt Engine"]
    end

    subgraph TB1["TRUST BOUNDARY 1: Identity & Ingress Security Gateway"]
        PoP["PoP Token Validator<br/>• RFC 7800 'cnf' Claim Check<br/>• Strict Max TTL (15m)<br/>• Audience & Scope Binding"]
    end

    subgraph TB2["TRUST BOUNDARY 2: Runtime Tool Isolation & Policy Enforcement"]
        Proxy["Secure MCP Proxy<br/>• RBAC Policy Matrix<br/>• Argument Injection Filter<br/>• Structured Telemetry Emitter"]
    end

    subgraph TB3["TRUST BOUNDARY 3: Core Enterprise Infrastructure & Data"]
        Tools["Internal Tools & Data<br/>(Telemetry, Identity Graph)"]
    end

    UserEngine -->|"(1) Untrusted JSON-RPC Invocation"| PoP
    PoP -->|"(2) Verified Cryptographic Claims"| Proxy
    Proxy -->|"(3) Sanitized & Authorized Execution"| Tools

    classDef untrusted fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000;
    classDef boundary fill:#f3f4f6,stroke:#374151,stroke-width:1px,stroke-dasharray: 5 5,color:#000;
    classDef nodeStyle fill:#ffffff,stroke:#1e3a8a,stroke-width:2px,color:#000;

    class UED untrusted;
    class TB1,TB2,TB3 boundary;
    class UserEngine,PoP,Proxy,Tools nodeStyle;

    sequenceDiagram
    autonumber
    actor Agent as Autonomous Agent
    participant Ingress as PoP Token Validator
    participant Proxy as Secure MCP Proxy
    participant SIEM as Datadog / SIEM Logger
    participant Backend as Enterprise Tool Backend

    Agent->>Ingress: JSON-RPC Call + Bearer PoP Token
    alt Invalid Token / Expired / Missing 'cnf'
        Ingress-->>Agent: 401 Unauthorized (TokenValidationError)
    else Token Verified
        Ingress->>Proxy: Authenticated Claims & Request Payload
        Proxy->>Proxy: Evaluate RBAC (Role vs ALLOWED_TOOLS)
        Proxy->>Proxy: Recursive Regex Argument Sanitization
        alt Policy Violation / Dangerous Pattern Detected
            Proxy->>SIEM: Emit JSON {"status": "BLOCKED", "event_type": "mcp_security_block"}
            Proxy-->>Agent: JSON-RPC Error (-32000 Policy Violation)
        else Validation Passed
            Proxy->>SIEM: Emit JSON {"status": "ALLOWED", "event_type": "mcp_tool_execution"}
            Proxy->>Backend: Execute Tool Method
            Backend-->>Proxy: Execution Output
            Proxy-->>Agent: JSON-RPC Success Result
        end
    end

    STRIDE Threat Model & MitigationsSTRIDE CategorySpecific Agent Threat VectorArchitectural MitigationImplementation ComponentSpoofingCompromised bearer token replayed by malicious agent or rogue workload.Mandate short-lived JWTs bound to ephemeral keys via RFC 7800 cnf (confirmation) claims; enforce strict audience checking.src/identity/token_validator.pyTamperingTool parameters altered via indirect prompt injection (e.g., passing --namespace=kube-system or shell metachars).Recursive regex parameter validation blocking CLI argument switches, null bytes, command substitution, and path traversal.src/mcp_proxy/proxy.py (_validate_arguments)RepudiationUnaudited tool execution by autonomous non-human actors across microservices.Structured JSON audit logging capturing timestamps, tool names, sub/caller_id, status (ALLOWED/BLOCKED), and latency.src/mcp_proxy/proxy.py (_emit_telemetry)Information DisclosureUnauthorized agent accessing privileged identity graph or cluster telemetry.Strict RBAC policy whitelist (ALLOWED_TOOLS) restricting tool execution to validated token roles.src/mcp_proxy/proxy.py (ALLOWED_TOOLS)Denial of ServiceLong-lived token persistence or recursive malformed JSON-RPC payloads exhausting proxy memory.Bounded token TTL enforcement ($\le 900\text{s}$) and deterministic JSON parse recovery returning standard error payloads.token_validator.py & proxy.pyElevation of PrivilegeConfused deputy attack: Low-privilege agent invoking high-privilege tool methods.Multi-tier validation: token scope verification followed by method-level RBAC policy evaluation before tool routing.PoPTokenValidator + SecureMCPProxyTelemetry Schema & SIEM / Observability IngestionAll proxy decisions generate a standardized JSON audit record:JSON{
  "timestamp": 1787859388.378,
  "event_type": "mcp_security_block",
  "tool_name": "read_telemetry",
  "status": "BLOCKED",
  "caller_id": "agent-service-account-01",
  "latency_ms": 0.379,
  "details": "Dangerous parameter pattern detected: 'cluster-1; cat /etc/passwd'"
}
