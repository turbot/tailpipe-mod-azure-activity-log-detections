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
    detection.diagnostic_setting_deleted,
  ]

  tags = merge(local.monitor_common_tags, {
    type = "Benchmark"
  })
}

detection "diagnostic_setting_deleted" {
  title           = "Diagnostic Setting Deleted"
  description     = "Detect when an Azure diagnostic setting is deleted, potentially impacting monitoring, logging, and alerting capabilities, which may reduce visibility into resource activities."
  documentation   = file("./detections/docs/diagnostic_setting_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.diagnostic_setting_deleted

  tags = merge(local.monitor_common_tags, {
    mitre_attack_ids = "TA0040:T1565.001, TA0005:T1562.002"
  })
}

query "diagnostic_setting_deleted" {
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