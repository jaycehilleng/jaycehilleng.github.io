// Azure Bicep Module: Agent Workload Identity
// Implemented: a user-assigned managed identity for the agent container task (no stored secrets).
// Designed: register the agent as an Entra Agent ID and add a federated identity credential
// (Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials) for OIDC assertion exchange.
targetScope = 'resourceGroup'

@description('Environment name prefix')
param environmentName string = 'mcp-sandbox-prod'

@description('Unique identifier for the agent workload application')
param agentAppName string = '${environmentName}-entra-agent-id'

// 1. User-Assigned Managed Identity for Agent Container Task
resource agentManagedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: agentAppName
  location: resourceGroup().location
}

// Outputs
output agentIdentityClientId string = agentManagedIdentity.properties.clientId
output agentIdentityPrincipalId string = agentManagedIdentity.properties.principalId
output agentIdentityResourceId string = agentManagedIdentity.id
