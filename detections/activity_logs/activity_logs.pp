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
    detection.activity_logs_detect_application_gateways_modify_delete,
    detection.activity_logs_detect_application_security_groups_modify_delete,
    detection.activity_logs_detect_container_registries_create_delete,
    detection.activity_logs_detect_firewalls_modify_delete,
    detection.activity_logs_detect_grant_permissions_detection,
    detection.activity_logs_detect_keyvault_secrets_modify_delete,
    detection.activity_logs_detect_keyvaults_modify_delete,
    detection.activity_logs_detect_kubernetes_clusters_create_delete,
    detection.activity_logs_detect_kubernetes_pods_delete,
    detection.activity_logs_detect_network_security_groups_modify_delete,
    detection.activity_logs_detect_virtual_networks_create_modify_delete,
    detection.activity_logs_detect_virtual_networks_modify_delete,
    detection.activity_logs_detect_vpn_connections_modify_delete,
    detection.activity_logs_detect_storage_account_key_regenerated,
    detection.activity_logs_detect_event_hub_auth_rule_create_update,
    detection.activity_logs_detect_event_hub_delete,
    detection.activity_logs_detect_automation_webhook_create,
    detection.activity_logs_detect_automation_runbook_delete,
    detection.activity_logs_detect_automation_account_create,
    detection.activity_logs_detect_automation_runbook_create_modify,
    detection.activity_logs_detect_virtual_network_device_modify,
    detection.activity_logs_detect_resource_group_delete,
    detection.activity_logs_detect_network_watcher_delete,
    detection.activity_logs_detect_storage_blob_container_access_modify,
    detection.activity_logs_detect_diagnostic_settings_delete,
    detection.activity_logs_detect_virtual_machine_command_execution,
    detection.activity_logs_detect_dns_zone_modify_delete,
    detection.activity_logs_detect_firewall_policies_modify_delete,
    detection.activity_logs_detect_firewall_rules_modify_delete,
    detection.activity_logs_detect_frontdoor_firewall_policies_delete
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

detection "activity_logs_detect_storage_account_key_regenerated" {
  title       = "Detect Storage accounts key regenerated"
  description = "Detects the regeneration of Storage accounts key."
  severity    = "low"
  query       = query.activity_logs_detect_storage_account_key_regenerated

  references = [
    "https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_event_hub_auth_rule_create_update" {
  title       = "Detect Event Hubs Auth Rule Created or Updated"
  description = "Detects when a Azure Event Hubs Auth Rule is created or updated."
  severity    = "medium"
  query       = query.activity_logs_detect_event_hub_auth_rule_create_update

  references = [
    "https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_event_hub_delete" {
  title       = "Detect Event Hubs Deleted"
  description = "Detects the deletion of Azure Event Hubs."
  severity    = "medium"
  query       = query.activity_logs_detect_event_hub_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about",
    "https://azure.microsoft.com/en-in/services/event-hubs/",
    "https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-features",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_webhook_create" {
  title       = "Detect Automation Account Webhook Created"
  description = "Detects the creation of Azure Automation account webhook."
  severity    = "low"
  query       = query.activity_logs_detect_automation_webhook_create

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://www.ciraltos.com/webhooks-and-azure-automation-runbooks/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_runbook_delete" {
  title       = "Detect Automation Account Runbook Deleted"
  description = "Detects the deletion of Azure Automation account runbook."
  severity    = "low"
  query       = query.activity_logs_detect_automation_runbook_delete

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_account_create" {
  title       = "Detect Automation Account Created"
  description = "Detects the creation of Azure Automation account."
  severity    = "low"
  query       = query.activity_logs_detect_automation_account_create

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_runbook_create_modify" {
  title       = "Detect Automation Runbook Created or Modified"
  description = "Detects the creation or modification of Azure Automation runbook."
  severity    = "low"
  query       = query.activity_logs_detect_automation_runbook_create_modify

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_virtual_network_device_modify" {
  title       = "Detect Virtual Network Device Modified"
  description = "Detects the modification of Azure Virtual Network Device."
  severity    = "low"
  query       = query.activity_logs_detect_virtual_network_device_modify

  references = [
    "https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_resource_group_delete" {
  title       = "Detect Resource Group Deleted"
  description = "Detects the deletion of Azure Resource Group."
  severity    = "low"
  query       = query.activity_logs_detect_resource_group_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_network_watcher_delete" {
  title       = "Detect Network Watcher Deleted"
  description = "Detects the deletion of Azure Network Watche."
  severity    = "low"
  query       = query.activity_logs_detect_network_watcher_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_storage_blob_container_access_modify" {
  title       = "Detect Storage Blob Container Access Modified"
  description = "Detects the modification of Azure Storage Blob Container access."
  severity    = "low"
  query       = query.activity_logs_detect_storage_blob_container_access_modify

  references = [
    "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_diagnostic_settings_delete" {
  title       = "Detect Diagnostic Setting Deletion"
  description = "Detects the deletion of Azure diagnostic setting."
  severity    = "medium"
  query       = query.activity_logs_detect_diagnostic_settings_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_virtual_machine_command_execution" {
  title       = "Detect Virtual Machine Command Execution"
  description = "Detects the command execution virtual machine"
  severity    = "medium"
  query       = query.activity_logs_detect_virtual_machine_command_execution

  references = [
    "https://adsecurity.org/?p=4277",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#virtual-machine-contributor",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_dns_zone_modify_delete" {
  title       = "Detect DNS Zone Modified or Deleted"
  description = "Detects when a DNS zone is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_dns_zone_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_firewall_policies_modify_delete" {
  title       = "Detect Firewall Policy Modified or Deleted"
  description = "Detects when a firewall policy  is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_policies_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_firewall_rules_modify_delete" {
  title       = "Detect Firewall Rule Modified or Deleted"
  description = "Detects when a firewall Rules  is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_rules_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations"
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_frontdoor_firewall_policies_delete" {
  title       = "Detect Front Door WAF  Policy Deletion"
  description = "Detects the deletion of Front Door WAF policy."
  severity    = "low"
  query       = query.activity_logs_detect_frontdoor_firewall_policies_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#networking"
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

query "activity_logs_detect_storage_account_key_regenerated" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/regenerateKey/action'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_event_hub_auth_rule_create_update" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.EventHub/namespaces/authorizationRules/write'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_event_hub_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.EventHub/namespaces/eventhubs/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_automation_webhook_create" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Automation/automationAccounts/webhooks/action',
        'Microsoft.Automation/automationAccounts/webhooks/write'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_automation_runbook_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Automation/automationAccounts/runbooks/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_automation_account_create" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Automation/automationAccounts/write'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_automation_runbook_create_modify" {
  sql = <<-EOQ
    select
     ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Automation/automationAccounts/runbooks/draft/write',
        'Microsoft.Automation/automationAccounts/runbooks/write',
        'Microsoft.Automation/automationAccounts/runbooks/publish/action',
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_virtual_network_device_modify" {
  sql = <<-EOQ
    select
     ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Network/networkInterfaces/tapConfigurations/write',
        'Microsoft.Network/networkInterfaces/tapConfigurations/delete',
        'Microsoft.Network/networkInterfaces/write',
        'Microsoft.Network/networkInterfaces/delete',
        'Microsoft.Network/networkInterfaces/join/action',
        'Microsoft.Network/networkVirtualAppliances/delete',
        'Microsoft.Network/networkVirtualAppliances/write',
        'Microsoft.Network/virtualHubs/write',
        'Microsoft.Network/virtualHubs/delete',
        'Microsoft.Network/virtualRouters/write',
        'Microsoft.Network/virtualRouters/delete'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_resource_group_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Resources/subscriptions/resourcegroups/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_network_watcher_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkWatchers/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_storage_blob_container_access_modify" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/blobServices/containers/write'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_diagnostic_settings_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'microsoft.insights/diagnosticSettings/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_virtual_machine_command_execution" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Compute/virtualMachines/runCommand/action'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_dns_zone_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Network/dnsZones/delete',
        'Microsoft.Network/dnsZones/write'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_keys_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Network/dnsZones/delete',
        'Microsoft.Network/dnsZones/write'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_policies_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Network/firewallPolicies/write',
        'Microsoft.Network/firewallPolicies/delete',
        'Microsoft.Network/firewallPolicies/join/action',
        'Microsoft.Network/firewallPolicies/certificates/action'
      )
      and
        status = 'Succeeded'
    order by
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_firewall_rules_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Network/firewallPolicies/ruleCollectionGroups/write',
        'Microsoft.Network/firewallPolicies/ruleCollectionGroups/delete',
        'Microsoft.Network/firewallPolicies/ruleGroups/write',
        'Microsoft.Network/firewallPolicies/ruleGroups/delete'
      )
      and
        status = 'Succeeded'
    order by
      timestamp DESC;
  EOQ
}

query "activity_logs_detect_frontdoor_firewall_policies_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/delete'
      and
        status = 'Succeeded'
    order by
      timestamp DESC;
  EOQ
}
