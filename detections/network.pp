locals {
  network_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/Network"
  })
}

benchmark "network_detections" {
  title       = "Network Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Network activity logs."
  type        = "detection"
  children = [
    detection.network_application_gateway_deleted,
    detection.network_application_security_group_deleted,
    detection.network_firewall_deleted,
    detection.network_security_group_updated,
    detection.network_security_group_deleted,
    detection.virtual_network_updated,
    detection.virtual_network_deleted,
    detection.network_vpn_connection_updated,
    detection.network_vpn_connection_deleted,
    detection.network_watcher_deleted,
    detection.network_firewall_policy_deleted,
    detection.network_firewall_rule_updated,
    detection.network_firewall_rule_deleted,
    detection.network_dns_zone_deleted
  ]

  tags = merge(local.network_common_tags, {
    type = "Benchmark"
  })
}

# Detections

detection "network_application_gateway_deleted" {
  title           = "Network Application Gateway Deleted"
  description     = "Detect when an Azure Application Gateway was deleted, which may disrupt application traffic delivery and impact availability or security controls."
  documentation   = file("./detections/docs/network_application_gateway_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.network_application_gateway_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_application_security_group_deleted" {
  title           = "Network Application Security Group Deleted"
  description     = "Detect when an Azure Application Security Group was deleted, which may impact security by disrupting access controls or application delivery."
  documentation   = file("./detections/docs/network_application_security_group_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.network_application_security_group_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_firewall_deleted" {
  title           = "Network Firewall Deleted"
  description     = "Detect when an Azure Firewall is deleted, potentially leaving your network vulnerable by removing critical security controls and exposing resources to unauthorized access or threats."
  documentation   = file("./detections/docs/network_firewall_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.network_firewall_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_security_group_updated" {
  title           = "Network Security Group Updated"
  description     = "Detect when an Azure Network Security Group is updated, which may impact security rules and network posture by altering traffic filtering or access controls."
  documentation   = file("./detections/docs/network_security_group_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.network_security_group_updated

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "network_security_group_deleted" {
  title           = "Network Security Group Deleted"
  description     = "Detect when an Azure Network Security Group was deleted, which may disrupt traffic filtering and increase the risk of exposure to unauthorized access or threats."
  documentation   = file("./detections/docs/network_security_group_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.network_security_group_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "virtual_network_updated" {
  title           = "Virtual Network Updated"
  description     = "Detect when an Azure Virtual Network was updated, which may impact connectivity and security by modifying configurations such as subnets, peerings, or access controls."
  documentation   = file("./detections/docs/virtual_network_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.virtual_network_updated

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "virtual_network_deleted" {
  title           = "Virtual Network Deleted"
  description     = "Detect when an Azure Virtual Network was deleted, potentially disrupting connectivity, removing critical configurations, and exposing resources to communication failures or security risks."
  documentation   = file("./detections/docs/virtual_network_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.virtual_network_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_vpn_connection_updated" {
  title           = "Network VPN Connection Updated"
  description     = "Detect when an Azure VPN connection was updated, which may alter network connectivity, modify security configurations, or introduce risks such as unauthorized access or disrupted communication."
  documentation   = file("./detections/docs/network_vpn_connection_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.network_vpn_connection_updated

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "network_vpn_connection_deleted" {
  title           = "Network VPN Connection Deleted"
  description     = "Detect when an Azure VPN connection was deleted, potentially disrupting network connectivity and impacting communication between on-premises and cloud resources or between different networks."
  documentation   = file("./detections/docs/network_vpn_connection_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.network_vpn_connection_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_watcher_deleted" {
  title           = "Network Watcher Deleted"
  description     = "Detect when an Azure Network Watcher was deleted, which may reduce network monitoring capabilities, impair visibility into traffic patterns, and hinder troubleshooting efforts."
  documentation   = file("./detections/docs/network_watcher_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.network_watcher_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_firewall_policy_deleted" {
  title           = "Network Firewall Policy Deleted"
  description     = "Detect when an Azure Firewall policy was deleted, potentially leaving the network unprotected by removing critical security configurations, exposing resources to unauthorized access or threats."
  documentation   = file("./detections/docs/network_firewall_policy_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.network_firewall_policy_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_firewall_rule_updated" {
  title           = "Network Firewall Rule Updated"
  description     = "Detect when an Azure Firewall rule is updated, potentially altering network traffic filtering, modifying access controls, or introducing risks such as weakened security defenses."
  documentation   = file("./detections/docs/network_firewall_rule_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.network_firewall_rule_updated

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "network_firewall_rule_deleted" {
  title           = "Network Firewall Rule Deleted"
  description     = "Detect when an Azure Firewall rule was deleted, potentially exposing the network to unfiltered traffic by removing critical traffic filtering and access controls."
  documentation   = file("./detections/docs/network_firewall_rule_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.network_firewall_rule_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "network_dns_zone_deleted" {
  title           = "Network DNS Zone Deleted"
  description     = "Detect when an Azure DNS Zone was deleted, which may disrupt domain name resolution, impact application availability, and interrupt communication between resources."
  documentation   = file("./detections/docs/network_dns_zone_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.network_dns_zone_deleted

  tags = merge(local.network_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

# Queries

query "network_application_gateway_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/applicationGateways/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_application_security_group_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/applicationSecurityGroups/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_firewall_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/azureFirewalls/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_firewall_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/azureFirewalls/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_security_group_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkSecurityGroups/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_security_group_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkSecurityGroups/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "virtual_network_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/virtualNetworks/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "virtual_network_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/virtualNetworks/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_vpn_connection_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/vpnGateways/vpnConnections/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_vpn_connection_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/vpnGateways/vpnConnections/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_watcher_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/networkWatchers/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_firewall_policy_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_firewall_policy_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_firewall_rule_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/ruleGroups/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_firewall_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/firewallPolicies/ruleGroups/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "network_dns_zone_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/dnsZones/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
