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
    detection.automation_account_runbook_deleted,
  ]

  tags = merge(local.automation_common_tags, {
    type = "Benchmark"
  })
}

detection "automation_account_runbook_deleted" {
  title           = "Automation Account Runbook Deleted"
  description     = "Detect when an Azure Automation account runbook was deleted, providing visibility into significant changes that may impact automation, orchestration, or operational workflows."
  documentation   = file("./detections/docs/automation_account_runbook_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.automation_account_runbook_deleted

  tags = merge(local.automation_common_tags, {
    mitre_attack_ids = "TA0040:T1485, TA0040:T1531"
  })
}

query "automation_account_runbook_deleted" {
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
