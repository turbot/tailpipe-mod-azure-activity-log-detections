locals {
  activity_log_monitor_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/Monitor"
  })
}

benchmark "activity_logs_monitor_detections" {
  title       = "Monitor Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Monitor activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_diagnostic_setting_deletions,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

detection "activity_logs_detect_diagnostic_setting_deletions" {
  title       = "Detect Diagnostic Setting Deletions"
  description = "Detects the deletion of Azure diagnostic setting."
  severity    = "medium"
  query       = query.activity_logs_detect_diagnostic_setting_deletions


  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "activity_logs_detect_diagnostic_setting_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'microsoft.insights/diagnosticSettings/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}