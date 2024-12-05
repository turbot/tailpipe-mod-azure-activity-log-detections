detection_benchmark "activity_logs_network_detections" {
  title = "Activity Log Network Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Network activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_application_gateways_modify_delete,
    detection.activity_logs_detect_application_security_groups_modify_delete,
    detection.activity_logs_detect_firewalls_modify_delete,
    detection.activity_logs_detect_network_security_groups_modify_delete,
    detection.activity_logs_detect_virtual_networks_create_modify_delete,
    detection.activity_logs_detect_virtual_networks_modify_delete,
    detection.activity_logs_detect_vpn_connections_modify_delete,
    detection.activity_logs_detect_virtual_network_device_modify,
    detection.activity_logs_detect_network_watcher_delete,
    detection.activity_logs_detect_firewall_policies_modify_delete,
    detection.activity_logs_detect_firewall_rules_modify_delete,
    detection.activity_logs_detect_dns_zone_modify_delete,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/Network"
  })
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