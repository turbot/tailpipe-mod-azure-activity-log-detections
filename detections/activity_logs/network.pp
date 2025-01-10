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
    detection.activity_logs_detect_application_gateways_deletions,
    detection.activity_logs_detect_application_security_groups_deletions,
    detection.activity_logs_detect_firewalls_updates,
    detection.activity_logs_detect_firewalls_deletions,
    detection.activity_logs_detect_network_security_groups_updates,
    detection.activity_logs_detect_network_security_groups_deletions,
    detection.activity_logs_detect_virtual_networks_modified,
    detection.activity_logs_detect_virtual_networks_deletions,
    detection.activity_logs_detect_vpn_connections_updates,
    detection.activity_logs_detect_vpn_connections_deletions,
    detection.activity_logs_detect_network_watchers_deletions,
    detection.activity_logs_detect_firewall_policies_updates,
    detection.activity_logs_detect_firewall_policies_deletions,
    detection.activity_logs_detect_firewall_rules_updates,
    detection.activity_logs_detect_firewall_rules_deletions,
    detection.activity_logs_detect_dns_zones_deletions
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

# Detections

detection "activity_logs_detect_application_gateways_deletions" {
  title       = "Detect Application Gateways Deletions"
  description = "Detect Azure Application Gateways to check for deletions that may disrupt application traffic delivery."
  severity    = "medium"
  query       = query.activity_logs_detect_application_gateways_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_application_security_groups_deletions" {
  title       = "Detect Application Security Groups Deletions"
  description = "Detect Azure Application Security Groups to check for deletions that may impact security or disrupt application delivery."
  severity    = "medium"
  query       = query.activity_logs_detect_application_security_groups_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewalls_updates" {
  title       = "Detect Firewalls Updates"
  description = "Detect Azure Firewalls to check for write operations that may indicate configuration changes impacting network security."
  severity    = "medium"
  query       = query.activity_logs_detect_firewalls_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewalls_deletions" {
  title       = "Detect Firewalls Deletions"
  description = "Detect Azure Firewalls to check for deletions that may leave your network vulnerable."
  severity    = "high"
  query       = query.activity_logs_detect_firewalls_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_network_security_groups_updates" {
  title       = "Detect Network Security Groups Updates"
  description = "Detect Azure Network Security Groups to check for write operations that may impact security rules and network posture."
  severity    = "medium"
  query       = query.activity_logs_detect_network_security_groups_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_network_security_groups_deletions" {
  title       = "Detect Network Security Groups Deletions"
  description = "Detect Azure Network Security Groups to check for deletions that may disrupt traffic filtering and increase risk of exposure."
  severity    = "high"
  query       = query.activity_logs_detect_network_security_groups_deletions

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

detection "activity_logs_detect_virtual_networks_deletions" {
  title       = "Detect Virtual Networks Deletions"
  description = "Detect Azure Virtual Networks to check for deletions that may disrupt connectivity or result in loss of critical configurations."
  severity    = "high"
  query       = query.activity_logs_detect_virtual_networks_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_vpn_connections_updates" {
  title       = "Detect VPN Connections Updates"
  description = "Detect Azure VPN Connections to check for write operations that may alter network connectivity or introduce risks."
  severity    = "medium"
  query       = query.activity_logs_detect_vpn_connections_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_vpn_connections_deletions" {
  title       = "Detect VPN Connections Deletions"
  description = "Detect Azure VPN Connections to check for deletions that may disrupt network connectivity."
  severity    = "high"
  query       = query.activity_logs_detect_vpn_connections_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_network_watchers_deletions" {
  title       = "Detect Network Watchers Deletions"
  description = "Detect Azure Network Watchers to check for deletions that may reduce network monitoring capabilities."
  severity    = "medium"
  query       = query.activity_logs_detect_network_watchers_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_policies_updates" {
  title       = "Detect Firewall Policies Updates"
  description = "Detect Azure Firewall Policies to check for write operations that may impact network security configurations."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_policies_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_policies_deletions" {
  title       = "Detect Firewall Policies Deletions"
  description = "Detect Azure Firewall Policies to check for deletions that may leave the network unprotected."
  severity    = "high"
  query       = query.activity_logs_detect_firewall_policies_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_rules_updates" {
  title       = "Detect Firewall Rules Updates"
  description = "Detect Azure Firewall Rules to check for write operations that may change network traffic filtering."
  severity    = "medium"
  query       = query.activity_logs_detect_firewall_rules_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_firewall_rules_deletions" {
  title       = "Detect Firewall Rules Deletions"
  description = "Detect Azure Firewall Rules to check for deletions that may expose the network to unfiltered traffic."
  severity    = "high"
  query       = query.activity_logs_detect_firewall_rules_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_dns_zones_deletions" {
  title       = "Detect DNS Zones Deletions"
  description = "Detect Azure DNS Zones to check for deletions that may disrupt domain name resolution and availability."
  severity    = "high"
  query       = query.activity_logs_detect_dns_zones_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

# Queries

query "activity_logs_detect_application_gateways_deletions" {
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

query "activity_logs_detect_application_security_groups_deletions" {
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

query "activity_logs_detect_firewalls_updates" {
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

query "activity_logs_detect_firewalls_deletions" {
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

query "activity_logs_detect_network_security_groups_updates" {
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

query "activity_logs_detect_network_security_groups_deletions" {
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

query "activity_logs_detect_virtual_networks_deletions" {
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
query "activity_logs_detect_vpn_connections_updates" {
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

query "activity_logs_detect_vpn_connections_deletions" {
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

query "activity_logs_detect_network_watchers_deletions" {
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

query "activity_logs_detect_firewall_policies_updates" {
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

query "activity_logs_detect_firewall_policies_deletions" {
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

query "activity_logs_detect_firewall_rules_updates" {
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

query "activity_logs_detect_firewall_rules_deletions" {
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

query "activity_logs_detect_dns_zones_deletions" {
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