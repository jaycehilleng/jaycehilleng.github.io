// Azure Bicep Module: Ephemeral MCP Agent Sandbox Environment & AI Gateway
targetScope = 'resourceGroup'

@description('Azure Region for resource deployment')
param location string = resourceGroup().location

@description('Environment name prefix')
param environmentName string = 'mcp-sandbox-prod'

@description('Container image for the isolated MCP tool execution sandbox')
param containerImage string = 'mcr.microsoft.com/azuredocs/aci-helloworld:latest'

@description('Publisher email for API Management gateway notifications')
param apimPublisherEmail string = 'admin@hillsecadvisors.com'

@description('Publisher name for API Management gateway')
param apimPublisherName string = 'Hill Security Advisors'

// 1. Log Analytics Workspace for Audit Trails & Diagnostic Logs
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${environmentName}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// 2. Azure Container Apps Environment (Isolated VNet Boundary)
resource caEnvironment 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: '${environmentName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

// 3. Ephemeral Sandbox Execution App (Micro-Kernel Isolation Tier)
resource sandboxApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: '${environmentName}-runner'
  location: location
  properties: {
    managedEnvironmentId: caEnvironment.id
    configuration: {
      ingress: {
        external: false // Private Ingress Only - Accessible solely via APIM Gateway
        targetPort: 8080
        transport: 'auto'
      }
    }
    template: {
      containers: [
        {
          name: 'mcp-tool-runner'
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
        }
      ]
      scale: {
        minReplicas: 0 // Scale to zero when idle
        maxReplicas: 5
      }
    }
  }
}

// 4. Azure API Management Service (Central AI Gateway Tier)
resource apimService 'Microsoft.ApiManagement/service@2023-05-01-preview' = {
  name: '${environmentName}-apim'
  location: location
  sku: {
    name: 'Basicv2'
    capacity: 1
  }
  properties: {
    publisherEmail: apimPublisherEmail
    publisherName: apimPublisherName
  }
}

// 5. APIM Backend Declaration for Internal Sandbox Container App
resource apimBackend 'Microsoft.ApiManagement/service/backends@2023-05-01-preview' = {
  parent: apimService
  name: 'mcp-sandbox-backend'
  properties: {
    description: 'Internal Container App Execution Sandbox'
    protocol: 'http'
    url: 'https://${sandboxApp.properties.configuration.ingress.fqdn}'
  }
}

// 6. Global APIM Inbound Security Policy (Declarative Binding from apim-policy.xml)
resource apimGlobalPolicy 'Microsoft.ApiManagement/service/policies@2023-05-01-preview' = {
  parent: apimService
  name: 'policy'
  properties: {
    value: loadTextContent('./apim-policy.xml')
    format: 'rawxml'
  }
}

// Outputs
output apimGatewayUrl string = apimService.properties.gatewayUrl
output sandboxContainerFqdn string = sandboxApp.properties.configuration.ingress.fqdn
