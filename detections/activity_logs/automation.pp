locals {
  activity_log_automation_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/Automation"
  })
}

benchmark "activity_logs_automation_detections" {
  title       = "Automation Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Automation activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_automation_runbook_deletions,
  ]

  tags = merge(local.activity_log_automation_detection_common_tags, {
    type    = "Benchmark"
  })
}

detection "activity_logs_detect_automation_runbook_deletions" {
  title       = "Detect Automation Account Runbook Deletions"
  description = "Detect the deletions of Azure Automation account runbook, providing visibility into significant changes that may impact automation and orchestration."
  severity    = "low"
  query       = query.activity_logs_detect_automation_runbook_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "activity_logs_detect_automation_runbook_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Automation/automationAccounts/runbooks/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
