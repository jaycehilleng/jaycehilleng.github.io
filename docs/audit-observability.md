# Architecture Specification: Continuous Audit & Observability (Artifact 3)

## 1. Overview
This specification defines the audit logging, telemetry schema, and security observability pipeline for the Zero-Trust MCP Gateway. Fields and queries are marked **Implemented** (emitted by the code today) or **Designed** (planned enrichment).

## 2. Telemetry Pipeline Architecture
- **Emitter (implemented):** `SecureMCPProxy._emit_telemetry` writes one JSON record per allow/block decision to standard output.
- **Ingestion (designed):** Container Apps console logs shipped to a Log Analytics custom table `MCP_SecurityEvent_CL` through a data collection rule, plus APIM diagnostic logs.
- **Alerting (designed):** KQL alert rules in Microsoft Sentinel / Azure Monitor (see [`iac/azure/queries.kql`](../iac/azure/queries.kql)).

## 3. Security Event Schema (`MCP_SecurityEvent_CL`)

### Implemented fields (emitted by the proxy today)

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | real | Unix epoch seconds when the decision was made. |
| `event_type` | string | `mcp_tool_execution` (allowed) or `mcp_security_block` (blocked). |
| `status` | string | `ALLOWED` or `BLOCKED`. |
| `tool_name` | string | JSON-RPC method requested. |
| `caller_id` | string | Token subject (`sub`) of the calling agent, or `anonymous`. |
| `latency_ms` | real | Time spent in the proxy decision. |
| `details` | string | Reason for a block (e.g., token validation failure, unauthorized role, dangerous parameter pattern). |

### Designed enrichment

| Field | Purpose |
| :--- | :--- |
| `correlation_id` | Trace a request across APIM and the proxy. |
| `client_ip` | Source of the invoking agent container. |
| `rule` | Machine-readable rule ID (e.g., `ARG_INJECTION`, `TOKEN_SIGNATURE`, `RBAC_DENY`). |
| `severity` | `INFORMATIONAL`, `WARNING`, `CRITICAL`. |

## 4. Security Audit Metrics
- **Block rate:** share of decisions with `status == "BLOCKED"`. *(Computable today)*
- **Token failures:** blocks whose `details` start with `Token validation failed`. *(Computable today)*
- **Proxy latency:** `latency_ms` percentiles per tool. *(Computable today)*
- **Injection blocks:** blocks whose `details` contain `Dangerous parameter pattern`. *(Computable today)*
