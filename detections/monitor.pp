locals {
  monitor_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/Monitor"
  })
}

benchmark "monitor_detections" {
  title       = "Monitor Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Monitor activity logs."
  type        = "detection"
  children = [
    detection.detect_diagnostic_setting_deletions,
  ]

  tags = merge(local.monitor_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_diagnostic_setting_deletions" {
  title           = "Detect Diagnostic Setting Deletions"
  description     = "Detects the deletion of Azure diagnostic settings, providing visibility into significant changes that may impact monitoring and alerting."
  documentation   = file("./detections/docs/detect_diagnostic_setting_deletions.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_diagnostic_setting_deletions


  tags = merge(local.monitor_common_tags, {
    mitre_attack_ids = "TA0040:T1565.001"
  })
}

query "detect_diagnostic_setting_deletions" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'microsoft.insights/diagnosticSettings/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}