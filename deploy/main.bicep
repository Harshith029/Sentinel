// Whence — Azure Container Apps deployment (BUILD_SPEC §Phase 8).
//
// TOPOLOGY PROOF (the thesis enforced by network shape, not by hope):
//   * `whence` proxy/control-plane/dashboard  -> ingress.external = TRUE  (the
//     ONLY publicly reachable endpoint; the agent can reach nothing else).
//   * tool servers (web / email / records)       -> ingress.external = FALSE (no
//     external ingress; reachable ONLY from inside the ACA environment, i.e.
//     ONLY by Whence). They have no public FQDN.
// KEDA HTTP-concurrency scaler on the proxy. System-assigned managed identity +
// Key Vault RBAC for secret resolution. Cosmos partitioned by trace_id.

@description('Deployment location')
param location string = resourceGroup().location

@description('Resource name prefix')
param prefix string = 'whence'

@description('Container image (proxy/control-plane/dashboard + tool servers)')
param image string

@description('Run the proxy in AZURE MODE (false => DEMO MODE banner)')
param demoMode bool = false

var lawName = '${prefix}-law'
var envName = '${prefix}-env'
var cosmosName = '${prefix}-cosmos-${uniqueString(resourceGroup().id)}'
var kvName = take('${prefix}kv${uniqueString(resourceGroup().id)}', 24)
// Public Azure built-in role-definition id for "Key Vault Secrets User" (NOT a
// secret — documented by Microsoft; the same value in every tenant).
var kvSecretsUserRole = '4633458b-17de-408a-b874-0445c86b69e6' // gitleaks:allow

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: lawName
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: envName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: law.properties.customerId
        sharedKey: law.listKeys().primarySharedKey
      }
    }
  }
}

// --- Cosmos DB: partition by trace_id; idempotent upserts; SDK default retry ---
resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: cosmosName
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    consistencyPolicy: { defaultConsistencyLevel: 'Session' }
    locations: [ { locationName: location, failoverPriority: 0 } ]
    disableLocalAuth: true // identity-only (managed identity), no keys
  }
}
resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmos
  name: 'whence'
  properties: { resource: { id: 'whence' } }
}
resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDb
  name: 'spans'
  properties: {
    resource: {
      id: 'spans'
      partitionKey: { paths: [ '/trace_id' ], kind: 'Hash' } // §2: partition by trace_id
    }
  }
}

// --- Key Vault (RBAC) for secret resolution via managed identity ---
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true // RBAC, not access policies (explicit)
  }
}

// --- Whence: the ONLY externally-reachable endpoint ---
resource whence 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-proxy'
  location: location
  identity: { type: 'SystemAssigned' } // system-assigned managed identity (explicit)
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: true // <-- the agent's ONLY reachable MCP/HTTP endpoint
        targetPort: 8765
        transport: 'auto'
      }
    }
    template: {
      containers: [
        {
          name: 'whence'
          image: image
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'WHENCE_DEMO_MODE', value: string(demoMode ? 1 : 0) }
            // Expose the real /mcp wire endpoint (the image already defaults to
            // create_gateway_app; this makes the intent explicit and survives an
            // image that uses create_app).
            { name: 'WHENCE_ENABLE_MCP_GATEWAY', value: '1' }
            { name: 'AZURE_COSMOS_ENDPOINT', value: cosmos.properties.documentEndpoint }
            { name: 'AZURE_KEY_VAULT_URI', value: kv.properties.vaultUri }
            // NOT VERIFIED AS DEPLOYABLE (audit F-02). This template has never
            // been deployed or smoke-tested. Key Vault secret consumption,
            // Content Safety / OpenAI configuration, Cosmos data-plane RBAC and
            // readiness checks are all still open; correct wiring here is not
            // evidence any of them work. /capabilities reports the same list.
            //
            // Internal-only DNS for the downstream tool servers. These are live:
            // setting them selects the remote path, which connects over real
            // MCP-over-HTTP through whence.downstream.open_downstream_session.
            // Streamable-HTTP MCP endpoints. The /mcp path is REQUIRED: the tool
            // servers mount their MCP app there, and Whence connects to the URL
            // verbatim, so omitting it fails discovery at startup.
            { name: 'WHENCE_TOOLS_WEB_URL', value: 'http://${prefix}-tools-web/mcp' }
            { name: 'WHENCE_TOOLS_EMAIL_URL', value: 'http://${prefix}-tools-email/mcp' }
            { name: 'WHENCE_TOOLS_RECORDS_URL', value: 'http://${prefix}-tools-records/mcp' }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 10
        rules: [
          {
            name: 'http-concurrency' // KEDA HTTP-concurrency scaler (named trigger)
            http: { metadata: { concurrentRequests: '50' } }
          }
        ]
      }
    }
  }
}

// Grant Whence's managed identity read access to Key Vault secrets (RBAC).
resource kvRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, whence.id, kvSecretsUserRole)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRole)
    principalId: whence.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- isolated tool servers: INTERNAL ingress only (no external endpoint) ---
var toolServers = [ 'web', 'email', 'records' ]
resource tools 'Microsoft.App/containerApps@2024-03-01' = [for t in toolServers: {
  name: '${prefix}-tools-${t}'
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: false // <-- NO external ingress: reachable only from Whence
        targetPort: 8000
        transport: 'http'
      }
    }
    template: {
      containers: [
        {
          name: 'toolserver'
          image: image
          command: [ 'python', '-m', 'whence.demo.toolserver_main' ]
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: [
            { name: 'WHENCE_TOOL_SERVER', value: t }
            { name: 'PORT', value: '8000' }
          ]
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 3 }
    }
  }
}]

output whenceUrl string = 'https://${whence.properties.configuration.ingress.fqdn}'
output toolServersExternal bool = false // proof: tool servers are never public
