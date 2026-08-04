# Architecture Specification: Continuous Audit & Observability (Artifact 3)

## 1. Overview
This specification defines the audit logging, telemetry schemas, and real-time security observability pipeline for the Zero-Trust Model Context Protocol (MCP) Gateway and Non-Human Identity (NHI) sidecar.

## 2. Telemetry Pipeline Architecture
- **Ingestion Tier:** Azure API Management (APIM) custom diagnostic logs and Container Apps stdout.
- **Log Analytics Workspace:** Centralized workspace for structured JSON security events.
- **Alerting Tier:** KQL-driven alert rules triggering Microsoft Sentinel / Azure Monitor alerts.

## 3. Structured Security Event Schema (`MCP_SecurityEvent_CL`)
All proxy inspection and token validation events emit a unified JSON payload:

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `TimeGenerated` | datetime | UTC timestamp of event execution. |
| `CorrelationId` | string | Unique GUID tracking the request across APIM and Proxy. |
| `EventType` | string | `XPIA_Detection`, `Token_Validation_Failure`, `Schema_Violation`, `Access_Granted`. |
| `Severity` | string | `INFORMATIONAL`, `WARNING`, `CRITICAL`. |
| `SubjectId` | string | Entra Agent Managed Identity Client ID or App Registration ID. |
| `ClientIP` | string | Source IP address of the invoking client or agent container. |
| `RuleTriggered` | string | Specific detection rule (e.g., `SUSPECTED_XPIA_PROMPT_INJECTION`, `INVALID_POP_BINDING`). |
| `RawPayloadSnippet` | string | Sanitized/redacted snippet of payload triggering the rule. |

## 4. Security Audit Metrics
- **XPIA Block Rate:** Percentage of inbound payload evaluations blocked due to prompt injection signatures.
- **Token Bound Check Failures:** Frequency of JWT rejections due to missing or invalid `cnf` claims or expired TTL.
- **Gateway Latency Impact:** Out-of-band proxy evaluation overhead in milliseconds ($t_{\text{proxy}} \le 15\text{ms}$).


