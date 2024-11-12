detection_benchmark "activity_log_detections" {
  title = "Azure Activity Log Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Activity logs."
  type = "detection"
  children = [
    detection.activity_logs_virtual_networks_create_modify_delete,
    detection.activity_logs_vpn_connection_modify_delete,
    detection.network_security_group_modify_delete
  ]
}

/*
 * Detections
 */

detection "activity_logs_virtual_networks_create_modify_delete" {
  title       = "Azure Virtual Network Creation, Modification, and Deletion Detection"
  description = "Detects events in Azure Activity Logs where virtual networks are created, updated, or deleted. This detection focuses on identifying potential unauthorized changes or critical modifications within the Azure environment."
  severity    = "high"
  query       = query.activity_logs_virtual_networks_create_modify_delete

  # references = [
  #   "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes",
  # ]

  # tags = merge(local.audit_logs_common_tags, {
  #   mitre_attack_ids = "TA0005:T1562:001"
  # })
}

detection "activity_logs_vpn_connection_modify_delete" {
  title       = "Azure VPN Connection Modification/Deletion Detection"
  description = "Identifies Azure Activity Log events where a VPN connection is modified or deleted, providing visibility into potential unauthorized changes or critical network modifications."
  severity    = "medium"
  query       = query.activity_logs_vpn_connection_modify_delete
}

detection "network_security_group_modify_delete" {
  title       = "Azure Network Security Groups Modifications/Deletions"
  description = "Identifies Azure Activity Log events where network security group configurations, including NSGs and related security rules, are modified or deleted. Useful for monitoring changes that may impact network security posture."
  severity    = "medium"
  query       = query.network_security_group_modify_delete
}

/*
 * Queries
 */

query "activity_logs_virtual_networks_create_modify_delete" {
  sql = <<-EOQ
    select
      tp_timestamp as timestamp,
      operation_name as action,
      caller as actor,
      resource_id as resource,
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

query "activity_logs_vpn_connection_modify_delete" {
  sql = <<-EOQ
    select
      tp_timestamp as timestamp,
      operation_name as action,
      caller as actor,
      resource_id as resource,
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

query "network_security_group_modify_delete" {
  sql = <<-EOQ
    SELECT
      tp_timestamp as timestamp,
      operation_name as action,
      caller as actor,
      resource_id as resource,
      status
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