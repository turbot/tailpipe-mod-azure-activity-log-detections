locals {
  automation_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/Automation"
  })
}

benchmark "automation_detections" {
  title       = "Automation Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Automation activity logs."
  type        = "detection"
  children = [
    detection.detect_automation_runbook_deletions,
  ]

  tags = merge(local.automation_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_automation_runbook_deletions" {
  title           = "Detect Automation Account Runbook Deletions"
  description     = "Detect the deletions of Azure Automation account runbook, providing visibility into significant changes that may impact automation and orchestration."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_automation_runbook_deletions

  tags = merge(local.automation_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_automation_runbook_deletions" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Automation/automationAccounts/runbooks/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
