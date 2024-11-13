locals {
  activity_log_detection_common_tags = {
    service  = "Azure/ActivityLog"
  }
}

detection_benchmark "activity_log_detections" {
  title = "Azure Activity Log Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_virtual_networks_create_modify_delete,
    detection.activity_logs_detect_vpn_connection_modify_delete,
    detection.activity_logs_detect_network_security_group_modify_delete,
    detection.activity_logs_detect_application_gateway_modify_delete,
    detection.activity_logs_detect_application_security_group_modify_delete,
    detection.activity_logs_detect_container_registry_create_delete,
    detection.activity_logs_detect_firewall_modify_delete,
    detection.activity_logs_detect_grant_permission_detection,
    detection.activity_logs_detect_keyvault_modify_delete,
    detection.activity_logs_detect_keyvault_secrets_modify_delete,
    detection.activity_logs_detect_virtual_network_modify_delete,
    detection.activity_logs_detect_kubernetes_cluster_create_delete,
    detection.activity_logs_detect_kubernetes_pods_delete
  ]
}

/*
 * Detections
 */

detection "activity_logs_detect_virtual_networks_create_modify_delete" {
  title       = "Azure Virtual Network Creation, Modification, and Deletion Detection"
  description = "Detects events in Azure Activity Logs where virtual networks are created, updated, or deleted. This detection focuses on identifying potential unauthorized changes or critical modifications within the Azure environment."
  severity    = "high"
  query       = query.activity_logs_detect_virtual_networks_create_modify_delete

  # references = [
  #   "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes",
  # ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_vpn_connection_modify_delete" {
  title       = "Azure VPN Connection Modification/Deletion Detection"
  description = "Identifies Azure Activity Log events where a VPN connection is modified or deleted, providing visibility into potential unauthorized changes or critical network modifications."
  severity    = "medium"
  query       = query.activity_logs_detect_vpn_connection_modify_delete

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_network_security_group_modify_delete" {
  title       = "Azure Network Security Groups Modifications/Deletions"
  description = "Identifies Azure Activity Log events where network security group configurations, including NSGs and related security rules, are modified or deleted. Useful for monitoring changes that may impact network security posture."
  severity    = "medium"
  query       = query.activity_logs_detect_network_security_group_modify_delete

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_application_gateway_modify_delete" {
  title       = "Azure Application Gateway Modified or Deleted"
  description = "Detects when a application gateway is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_application_gateway_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_application_security_group_modify_delete" {
  title       = "Azure Application Security Group Modified or Deleted"
  description = "Detects when a application security group is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_application_security_group_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_container_registry_create_delete" {
  title       = "Azure Container Registry Created or Deleted"
  description = "Detects when a Container Registry is created or deleted."
  severity    = "low"
  query       = query.activity_logs_detect_container_registry_create_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_firewall_modify_delete" {
  title       = "Azure Firewall Modified or Deleted"
  description = "Detects when a firewall is created, modified, or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_virtual_network_modify_delete" {
  title       = "Azure Virtual Network Modified or Deleted"
  description = "Detects when a Virtual Network is modified or deleted in Azure."
  severity    = "medium"
  query       = query.activity_logs_detect_virtual_network_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_grant_permission_detection" {
  title       = "Azure Permission Granted to an Account"
  description = "Detects IPs from which users grant access to others on Azure resources, and raises an alert when an unfamiliar source IP address is used."
  severity    = "medium"
  query       = query.activity_logs_detect_grant_permission_detection

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_keyvault_modify_delete" {
  title       = "Azure Key Vault Modified or Deleted"
  description = "Detects when a key vault is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_keyvault_secrets_modify_delete" {
  title       = "Azure Keyvault Secrets Modified or Deleted"
  description = "Detects when secrets are modified or deleted in Azure."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_secrets_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/security#microsoftkeyvault",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_kubernetes_cluster_create_delete" {
  title       = "Azure Kubernetes Cluster Created or Deleted"
  description = "Detects when a Azure Kubernetes Cluster is created or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_cluster_create_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
    "https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/",
    "https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_kubernetes_pods_delete" {
  title       = "Azure Kubernetes Pods Deleted"
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
      operation_name IN (
        'Microsoft.Network/virtualNetworks/write',
        'Microsoft.Network/virtualNetworks/delete'
      )
      and
        status = 'Succeeded'
    order by
      tp_timestamp desc;
  EOQ
}

query "activity_logs_detect_vpn_connection_modify_delete" {
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
      tp_timestamp desc;
  EOQ
}

query "activity_logs_detect_network_security_group_modify_delete" {
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
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_application_gateway_modify_delete" {
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
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_application_security_group_modify_delete" {
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
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_container_registry_create_delete" {
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
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_firewall_modify_delete" {
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
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_grant_permission_detection" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      AND
        status = 'Succeeded'
    ORDER BY
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_keyvault_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.KeyVault/vaults/write',
        'Microsoft.KeyVault/vaults/delete',
        'Microsoft.KeyVault/vaults/accessPolicies/write',
        'Microsoft.KeyVault/vaults/deploy/action'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_keyvault_secrets_modify_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.KeyVault/vaults/secrets/write',
        'Microsoft.KeyVault/vaults/secrets/delete',
        'Microsoft.KeyVault/vaults/secrets/backup/action',
        'Microsoft.KeyVault/vaults/secrets/purge/action',
        'Microsoft.KeyVault/vaults/secrets/update/action',
        'Microsoft.KeyVault/vaults/secrets/recover/action',
        'Microsoft.KeyVault/vaults/secrets/restore/action',
        'Microsoft.KeyVault/vaults/secrets/setSecret/action'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_virtual_network_modify_delete" {
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
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_kubernetes_cluster_create_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name IN (
        'Microsoft.Kubernetes/connectedClusters/write',
        'Microsoft.Kubernetes/connectedClusters/delete'
      )
      AND
        status = 'Succeeded'
    ORDER BY
      tp_timestamp DESC;
  EOQ
}

query "activity_logs_detect_kubernetes_pods_delete" {
  sql = <<-EOQ
    SELECT
      ${local.common_activity_logs_sql}
    FROM
      azure_activity_log
    WHERE
      operation_name = 'Microsoft.Kubernetes/connectedClusters/pods/delete'
      AND
        status = 'Succeeded'
    ORDER BY
      tp_timestamp DESC;
  EOQ
}