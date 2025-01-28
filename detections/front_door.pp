locals {
  front_door_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/FrontDoor"
  })
}

benchmark "front_door_detections" {
  title       = "Front Door Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Front Door activity logs."
  type        = "detection"
  children = [
    detection.front_door_firewall_policy_deleted
  ]

  tags = merge(local.front_door_common_tags, {
    type = "Benchmark"
  })
}

detection "front_door_firewall_policy_deleted" {
  title           = "Front Door Firewall Policy Deleted"
  description     = "Detect when a Front Door firewall policy was deleted, providing visibility into significant changes that may impact security by removing protections against malicious traffic."
  documentation   = file("./detections/docs/front_door_firewall_policy_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.front_door_firewall_policy_deleted

  tags = merge(local.front_door_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "front_door_firewall_policy_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp DESC;
  EOQ
}