detection_benchmark "activity_logs_frontdoor_detections" {
  title = "Activity Log Front Door Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Front Door activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_frontdoor_firewall_policies_delete
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/FrontDoor"
  })
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