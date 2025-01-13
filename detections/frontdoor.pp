locals {
  frontdoor_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/FrontDoor"
  })
}

benchmark "frontdoor_detections" {
  title       = "Front Door Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Front Door activity logs."
  type        = "detection"
  children = [
    detection.detect_frontdoor_firewall_policy_deletions
  ]

  tags = merge(local.frontdoor_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_frontdoor_firewall_policy_deletions" {
  title           = "Detect Front Door Policy Deletions"
  description     = "Detect the deletions of Front Door policies, providing insight into changes that may impact security."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_frontdoor_firewall_policy_deletions

  tags = merge(local.frontdoor_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_frontdoor_firewall_policy_deletions" {
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