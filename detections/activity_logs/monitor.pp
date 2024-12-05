detection_benchmark "activity_logs_monitor_detections" {
  title = "Activity Log Monitor Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Monitor activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_diagnostic_settings_delete,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/Monitor"
  })
}

detection "activity_logs_detect_diagnostic_settings_delete" {
  title       = "Detect Diagnostic Setting Deletion"
  description = "Detects the deletion of Azure diagnostic setting."
  severity    = "medium"
  query       = query.activity_logs_detect_diagnostic_settings_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings"
  ]

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_diagnostic_settings_delete" {
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