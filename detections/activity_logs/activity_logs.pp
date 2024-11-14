locals {
  activity_log_detection_common_tags = {
    service  = "Azure/Monitor"
  }
}

detection_benchmark "activity_log_detections" {
  title = "Activity Log Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_virtual_networks_create_modify_delete,
    detection.activity_logs_detect_vpn_connections_modify_delete,
    detection.activity_logs_detect_network_security_groups_modify_delete,
    detection.activity_logs_detect_application_gateways_modify_delete,
    detection.activity_logs_detect_application_security_groups_modify_delete,
    detection.activity_logs_detect_container_registries_create_delete,
    detection.activity_logs_detect_firewalls_modify_delete,
    detection.activity_logs_detect_grant_permissions_detection,
    detection.activity_logs_detect_keyvaults_modify_delete,
    detection.activity_logs_detect_keyvault_secrets_modify_delete,
    detection.activity_logs_detect_virtual_networks_modify_delete,
    detection.activity_logs_detect_kubernetes_clusters_create_delete,
    detection.activity_logs_detect_kubernetes_pods_delete
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections
 */

detection "activity_logs_detect_virtual_networks_create_modify_delete" {
  title       = "Detect Virtual Networks Created, Modified or Deleted"
  description = "Detects Azure Activity Log events for virtual network creation, updates, or deletion, highlighting unauthorized or critical modifications in the Azure environment."
  severity    = "high"
  query       = query.activity_logs_detect_virtual_networks_create_modify_delete

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_vpn_connections_modify_delete" {
  title       = "Detect VPN Connections Modified or Deleted"
  description = "Detects Azure Activity Log events for VPN connection modifications or deletions, offering insight into possible unauthorized changes or critical network adjustments."
  severity    = "medium"
  query       = query.activity_logs_detect_vpn_connections_modify_delete

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_network_security_groups_modify_delete" {
  title       = "Detect Network Security Groups Modified or Deleted"
  description = "Detects Azure Activity Log events involving modifications or deletions of network security group configurations, including NSGs and associated security rules, helping to monitor changes that could impact network security posture."
  severity    = "medium"
  query       = query.activity_logs_detect_network_security_groups_modify_delete

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_application_gateways_modify_delete" {
  title       = "Detect Application Gateways Modified or Deleted"
  description = "Detects when a application gateway is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_application_gateways_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_application_security_groups_modify_delete" {
  title       = "Detect Application Security Groups Modified or Deleted"
  description = "Detects modifications or deletions of an application gateway, providing insight into potential unauthorized changes or critical updates to application delivery and security configurations."
  severity    = "medium"
  query       = query.activity_logs_detect_application_security_groups_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_container_registries_create_delete" {
  title       = "Detect Container Registries Created or Deleted"
  description = "Detects the creation or deletion of a Container Registry, providing visibility into significant changes that may impact container management and deployment."
  severity    = "low"
  query       = query.activity_logs_detect_container_registries_create_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_firewalls_modify_delete" {
  title       = "Detect Firewalls Modified or Deleted"
  description = "Detects the creation, modification, or deletion of a firewall, highlighting potential changes that could impact network security and access controls."
  severity    = "medium"
  query       = query.activity_logs_detect_firewalls_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_virtual_networks_modify_delete" {
  title       = "Detect Virtual Networks Modified or Deleted"
  description = "Detects modifications or deletions of a Virtual Network in Azure, providing visibility into changes that may affect network structure and connectivity."
  severity    = "medium"
  query       = query.activity_logs_detect_virtual_networks_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_grant_permissions_detection" {
  title       = "Detect Permission Granted to an Account"
  description = "Identifies IPs from which users grant access to others on Azure resources and alerts on access granted from previously unrecognized IP addresses, helping to flag potential unauthorized access attempts."
  severity    = "medium"
  query       = query.activity_logs_detect_grant_permissions_detection

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_keyvaults_modify_delete" {
  title       = "Detect Key Vaults Modified or Deleted"
  description = "Detects when a key vault is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvaults_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_keyvault_secrets_modify_delete" {
  title       = "Detect Key Vault Secrets Modified or Deleted"
  description = "Detects when secrets are modified or deleted in Azure."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_secrets_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/security#microsoftkeyvault",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_kubernetes_clusters_create_delete" {
  title       = "Detect Kubernetes Clusters Created or Deleted"
  description = "Detects when a Azure Kubernetes Cluster is created or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_clusters_create_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
    "https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/",
    "https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_kubernetes_pods_delete" {
  title       = "Detect Kubernetes Pods Deleted"
  description = "Detects the deletion of Azure Kubernetes Pods."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_pods_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes",
  ]

  tags = local.activity_log_detection_common_tags
}

/*
 * Queries
 */

query "activity_logs_detect_virtual_networks_create_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Network/virtualNetworks/write',
        'Microsoft.Network/virtualNetworks/delete'
      )
      and
        status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_vpn_connections_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name IN (
        'microsoft.network/vpnGateways/vpnConnections/write',
        'microsoft.network/vpnGateways/vpnConnections/delete'
      )
      and
        status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_network_security_groups_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.Network/networkSecurityGroups/Write',
        'Microsoft.Network/networkSecurityGroups/Delete',
        'Microsoft.Network/networkSecurityGroups/securityRules/WRITE',
        'Microsoft.Network/networkSecurityGroups/securityRules/DELETE',
        'Microsoft.Network/networkSecurityGroups/join/action',
      )
      AND
        status = 'Succeeded'
    ORDER BY
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_application_gateways_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.Network/applicationGateways/write',
        'Microsoft.Network/applicationGateways/delete'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_application_security_groups_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.Network/applicationSecurityGroups/write',
        'Microsoft.Network/applicationSecurityGroups/delete'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_container_registries_create_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.ContainerRegistry/registries/write',
        'Microsoft.ContainerRegistry/registries/delete'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_firewalls_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.Network/azureFirewalls/write',
        'Microsoft.Network/azureFirewalls/delete'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_grant_permissions_detection" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvaults_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.KeyVault/vaults/write',
        'Microsoft.KeyVault/vaults/delete',
        'Microsoft.KeyVault/vaults/accessPolicies/write',
        'Microsoft.KeyVault/vaults/deploy/action'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secrets_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.KeyVault/vaults/secrets/write',
        'Microsoft.KeyVault/vaults/secrets/delete',
        'Microsoft.KeyVault/vaults/secrets/backup/action',
        'Microsoft.KeyVault/vaults/secrets/purge/action',
        'Microsoft.KeyVault/vaults/secrets/update/action',
        'Microsoft.KeyVault/vaults/secrets/recover/action',
        'Microsoft.KeyVault/vaults/secrets/restore/action',
        'Microsoft.KeyVault/vaults/secrets/setSecret/action'
      )
      and status = 'Succeeded'
    order by 
      timestamp desc;
  EOQ
}

query "activity_logs_detect_virtual_networks_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.Network/virtualNetworks/write',
        'Microsoft.Network/virtualNetworks/delete',
        'Microsoft.Network/virtualNetworkGateways/write',
        'Microsoft.Network/virtualNetworkGateways/delete'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_kubernetes_clusters_create_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Kubernetes/connectedClusters/write',
        'Microsoft.Kubernetes/connectedClusters/delete'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_kubernetes_pods_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Kubernetes/connectedClusters/pods/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}