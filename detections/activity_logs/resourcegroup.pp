locals {
  activity_log_resource_group_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/ResourceGroup"
  })
}

benchmark "activity_logs_resource_group_detections" {
  title       = "Resource Group Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Resource Group activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_resource_group_deletions
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

detection "activity_logs_detect_resource_group_deletions" {
  title       = "Detect Resource Group Deletions"
  description = "Detects the deletion of Azure Resource Group, providing visibility into significant changes that may impact resources."
  severity    = "low"
  query       = query.activity_logs_detect_resource_group_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "activity_logs_detect_resource_group_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Resources/subscriptions/resourcegroups/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
