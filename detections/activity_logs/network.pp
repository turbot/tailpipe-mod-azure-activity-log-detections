locals {
  activity_log_network_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/Network"
  })
}

benchmark "activity_logs_network_detections" {
  title       = "Network Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Network activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_application_gateway_deletions,
    detection.activity_logs_detect_application_security_group_deletions,
    detection.activity_logs_detect_firewall_updates,
    detection.activity_logs_detect_firewall_deletions,
    detection.activity_logs_detect_network_security_group_updates,
    detection.activity_logs_detect_network_security_group_deletions,
    detection.activity_logs_detect_virtual_networks_modified,
    detection.activity_logs_detect_virtual_network_deletions,
    detection.activity_logs_detect_vpn_connection_updates,
    detection.activity_logs_detect_vpn_connection_deletions,
    detection.activity_logs_detect_network_watcher_deletions,
    detection.activity_logs_detect_firewall_policy_updates,
    detection.activity_logs_detect_firewall_policy_deletions,
    detection.activity_logs_detect_firewall_rule_updates,
    detection.activity_logs_detect_firewall_rule_deletions,
    detection.activity_logs_detect_dns_zone_deletions
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

# Detections

detection "activity_logs_detect_application_gateway_deletions" {
  title       = "Detect Application Gateway Deletions"
  description = "Detect Azure Application Gateway to check for deletions that may disrupt application traffic delivery."
  severity    = "medium"
  query       = query.activity_logs_detect_application_gateway_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_application_security_group_deletions" {
  title       = "Detect Application Security Group Deletions"
  description = "Detect Azure Application Security Group to check for deletions that may impact security or disrupt application delivery."
  severity    = "medium"
  query       = query.activity_logs_detect_application_security_group_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_updates" {
  title       = "Detect Firewall Updates"
  description = "Detect Azure Firewall to check for write operations that may indicate configuration changes impacting network security."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_deletions" {
  title       = "Detect Firewall Deletions"
  description = "Detect Azure Firewall to check for deletions that may leave your network vulnerable."
  severity    = "high"
  query       = query.activity_logs_detect_firewall_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_network_security_group_updates" {
  title       = "Detect Network Security Group Updates"
  description = "Detect Azure Network Security Group to check for write operations that may impact security rules and network posture."
  severity    = "medium"
  query       = query.activity_logs_detect_network_security_group_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_network_security_group_deletions" {
  title       = "Detect Network Security Group Deletions"
  description = "Detect Azure Network Security Group to check for deletions that may disrupt traffic filtering and increase risk of exposure."
  severity    = "high"
  query       = query.activity_logs_detect_network_security_group_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_virtual_networks_modified" {
  title       = "Detect Virtual Networks Modified"
  description = "Detect Azure Virtual Networks to check for configuration updates that may impact connectivity and security."
  severity    = "medium"
  query       = query.activity_logs_detect_virtual_networks_modified

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_virtual_network_deletions" {
  title       = "Detect Virtual Network Deletions"
  description = "Detect Azure Virtual Network to check for deletions that may disrupt connectivity or result in loss of critical configurations."
  severity    = "high"
  query       = query.activity_logs_detect_virtual_network_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_vpn_connection_updates" {
  title       = "Detect VPN Connection Updates"
  description = "Detect Azure VPN Connection to check for write operations that may alter network connectivity or introduce risks."
  severity    = "medium"
  query       = query.activity_logs_detect_vpn_connection_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_vpn_connection_deletions" {
  title       = "Detect VPN Connection Deletions"
  description = "Detect Azure VPN Connection to check for deletions that may disrupt network connectivity."
  severity    = "high"
  query       = query.activity_logs_detect_vpn_connection_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_network_watcher_deletions" {
  title       = "Detect Network Watcher Deletions"
  description = "Detect Azure Network Watcher to check for deletions that may reduce network monitoring capabilities."
  severity    = "medium"
  query       = query.activity_logs_detect_network_watcher_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_policy_updates" {
  title       = "Detect Firewall Policy Updates"
  description = "Detect Azure Firewall Policy to check for write operations that may impact network security configurations."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_policy_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_policy_deletions" {
  title       = "Detect Firewall Policy Deletions"
  description = "Detect Azure Firewall Policy to check for deletions that may leave the network unprotected."
  severity    = "high"
  query       = query.activity_logs_detect_firewall_policy_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_rule_updates" {
  title       = "Detect Firewall Rule Updates"
  description = "Detect Azure Firewall Rule to check for write operations that may change network traffic filtering."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_rule_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_rule_deletions" {
  title       = "Detect Firewall Rule Deletions"
  description = "Detect Azure Firewall Rule to check for deletions that may expose the network to unfiltered traffic."
  severity    = "high"
  query       = query.activity_logs_detect_firewall_rule_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_dns_zone_deletions" {
  title       = "Detect DNS Zone Deletions"
  description = "Detect Azure DNS Zone to check for deletions that may disrupt domain name resolution and availability."
  severity    = "high"
  query       = query.activity_logs_detect_dns_zone_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

# Queries

query "activity_logs_detect_application_gateway_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/applicationGateways/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_application_security_group_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/applicationSecurityGroups/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/azureFirewalls/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/azureFirewalls/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_network_security_group_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkSecurityGroups/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_network_security_group_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkSecurityGroups/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_virtual_networks_modified" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/virtualNetworks/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_virtual_network_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/virtualNetworks/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_vpn_connection_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/vpnGateways/vpnConnections/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_vpn_connection_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/vpnGateways/vpnConnections/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_network_watcher_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkWatchers/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_policy_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_policy_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_rule_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/ruleGroups/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_firewall_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/ruleGroups/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_dns_zone_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/dnsZones/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}