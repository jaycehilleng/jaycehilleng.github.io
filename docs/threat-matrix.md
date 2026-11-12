# Enterprise Threat Matrix: OWASP Top 10 for LLM Applications & Google SAIF

**Author:** Jayce Hill | Principal AI Security Architect
**Framework Alignment:** OWASP Top 10 for LLM Applications (2025), Google Secure AI Framework (SAIF), NIST AI RMF

---

## Executive Summary

Agents that call tools over the Model Context Protocol (MCP) widen the attack surface beyond traditional application security. Indirect prompt injection, tool misuse, and non-human identity abuse need a threat model that maps each vector to a concrete control, and that is honest about which controls exist today.

Each mitigation below is marked **Implemented** (code and tests in this repo) or **Designed** (specified in the architecture docs, not yet built).

SAIF core elements referenced: **Foundations** (expand strong security foundations to the AI ecosystem), **Detection & Response** (extend detection and response to AI), **Automate** (automate defenses), **Harmonize** (harmonize platform-level controls), **Adapt** (adapt controls and create faster feedback loops), **Contextualize** (contextualize AI system risks in business processes).

---

## OWASP / SAIF Threat Mapping

| ID | OWASP LLM (2025) | Threat in an MCP Deployment | SAIF Element | Mitigation | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TR-01** | LLM01: Prompt Injection | Instructions embedded in retrieved content steer the agent into a harmful tool call with attacker-chosen arguments. | Foundations | Model-independent gate in `SecureMCPProxy`: tool allow-list, per-tool RBAC, recursive argument sanitization (command chaining, path traversal, CWE-88). | **Implemented** |
| **TR-02** | LLM01: Prompt Injection (indirect, via tool output) | Tool responses carry injected instructions back into the agent's context. | Detection & Response | Inspect tool responses before re-entry into agent context. | **Designed** |
| **TR-03** | LLM02: Sensitive Information Disclosure | Tool output leaks secrets or PII to the agent or user. | Harmonize | Output redaction on the response path. | **Designed** |
| **TR-04** | LLM03: Supply Chain | A compromised or impersonated MCP tool server is invoked. | Foundations | Explicit tool allow-list today; signed tool manifests and pinned server identities designed. CodeQL runs on this repo in CI. | **Implemented** (allow-list) / **Designed** (signing) |
| **TR-05** | LLM05: Improper Output Handling | Downstream systems execute model-generated arguments without validation. | Foundations | Argument sanitization implemented; per-tool JSON Schema validation designed. | **Implemented** / **Designed** |
| **TR-06** | LLM06: Excessive Agency | Agents hold broader tool access than the task requires. | Harmonize | Required scope per call, tool-level RBAC, default-deny Rego policy (authored; sidecar evaluation designed). | **Implemented** / **Designed** |
| **TR-07** | LLM10: Unbounded Consumption | Recursive or high-volume tool calls exhaust resources. | Adapt | Short token TTL implemented; APIM rate limiting and quotas designed. | **Designed** |
| **TR-08** | Non-human identity abuse (beyond the LLM Top 10) | Stolen, forged, or over-privileged agent credentials used for lateral movement. | Foundations | ES256 signature verification (rejects forged and `alg: none` tokens), 15-minute max TTL, audience and scope checks, `cnf` key-binding claim required. DPoP proof verification designed. | **Implemented** / **Designed** |

---

## Architectural Control Notes

### 1. Prompt Injection Defense
* **Threat vector:** untrusted data (documents, tickets, web pages) contains instruction overrides such as `IGNORE PREVIOUS INSTRUCTIONS` that steer tool calls.
* **Control (implemented):** the decision to execute is made outside the model. `SecureMCPProxy` checks identity, tool permission, and arguments on every `tools/call`, whatever the model was told.
* **Verification:** `src/mcp_proxy/test_proxy.py` and `src/mcp_proxy/test_integration.py` assert that injection payloads and unauthorized calls return a JSON-RPC error (`-32000`) and are logged as `BLOCKED`.
* **Limit:** pattern-based sanitization is one layer, not a complete prompt-injection defense; response-side inspection and per-tool schemas are designed next.

### 2. Non-Human Identity Governance
* **Threat vector:** a compromised agent token is used to move laterally.
* **Control (implemented):** tokens must be signed by the trusted key, carry the right audience and scope, include a `cnf` binding, and live no longer than 15 minutes.
* **Control (designed):** Entra Agent ID registration with a federated credential, and per-request DPoP proofs.

### 3. Tool Execution Isolation
* **Threat vector:** a malicious tool call achieves code execution in the tool runtime.
* **Control (implemented in IaC):** the tool container app has private ingress only (reachable through APIM) and scales to zero when idle (`iac/azure/main.bicep`).
* **Control (designed):** kernel-isolated execution (gVisor / Wasm), read-only filesystems, and restricted egress.

---

## Verification

Code-backed controls can be verified by running the test suite:

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m pytest src -v
```

Designed controls are specified in [`architecture-spec.md`](./architecture-spec.md) and [`identity-architecture.md`](./identity-architecture.md).
