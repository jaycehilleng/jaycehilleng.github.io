package mcp.authz

# Default deny: All tool invocations are blocked unless explicitly allowed
default allow = false

# Allow tool execution if all conditions are met
allow {
    # 1. Action must be a recognized tool call
    input.action == "tools/call"

    # 2. Token must have valid Proof-of-Possession and caller identity
    input.token.pop_valid == true
    input.token.sub != ""

    # 3. Evaluate tool-specific authorization rules
    is_authorized_tool
}

# Read-only tools require baseline agent execution scope
is_authorized_tool {
    input.tool_type == "read"
    input.token.scopes[_] == "agent:read"
}

# Write/mutate tools require elevated administrative scope and tenant match
is_authorized_tool {
    input.tool_type == "write"
    input.token.scopes[_] == "sec:admin"
    input.target_tenant_id == input.token.tenant_id
}

# Explicit violation reason for structured audit logging and telemetry
violation_reason = "UNAUTHORIZED_ACTION" {
    not allow
    input.action != "tools/call"
}

violation_reason = "INVALID_POP_TOKEN" {
    not allow
    input.action == "tools/call"
    input.token.pop_valid != true
}

violation_reason = "INSUFFICIENT_SCOPE_OR_TENANT_MISMATCH" {
    not allow
    input.action == "tools/call"
    input.token.pop_valid == true
    not is_authorized_tool
}