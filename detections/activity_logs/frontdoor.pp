locals {
  activity_log_frontdoor_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/FrontDoor"
  })
}

benchmark "activity_logs_frontdoor_detections" {
  title       = "Front Door Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Front Door activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_frontdoor_firewall_policy_deletions
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "activity_logs_detect_frontdoor_firewall_policy_deletions" {
  title       = "Detect Front Door WAF Policy Deletions"
  description = "Detect the deletions of Front Door WAF policies, providing insight into changes that may impact security."
  severity    = "low"
  query       = query.activity_logs_detect_frontdoor_firewall_policy_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "activity_logs_detect_frontdoor_firewall_policy_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp DESC;
  EOQ
}