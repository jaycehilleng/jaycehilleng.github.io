// Azure Bicep Module: Ephemeral MCP Agent Sandbox Environment
targetScope = 'resourceGroup'

param location string = resourceGroup().location
param environmentName string = 'mcp-sandbox-prod'
param containerImage string = 'mcr.microsoft.com/azuredocs/aci-helloworld:latest'

// 1. Log Analytics Workspace for Audit Trails
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

// 2. Azure Container Apps Environment (Isolated VNet)
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

// 3. Ephemeral Sandbox Execution App (Micro-Kernel Isolation)
resource sandboxApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: '${environmentName}-runner'
  location: location
  properties: {
    managedEnvironmentId: caEnvironment.id
    configuration: {
      ingress: {
        external: false // Private Ingress Only
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
          env: [
            {
              name: 'READ_ONLY_ROOT'
              value: 'true'
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0 // Scale to Zero when idle
        maxReplicas: 5
      }
    }
  }
}

output sandboxEnvironmentId string = caEnvironment.id
output sandboxAppFqdn string = sandboxApp.properties.configuration.ingress.fqdn
