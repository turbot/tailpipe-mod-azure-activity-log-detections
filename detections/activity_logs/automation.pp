detection_benchmark "activity_logs_automation_detections" {
  title = "Activity Log Automation Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Automation activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_automation_webhook_create,
    detection.activity_logs_detect_automation_runbook_delete,
    detection.activity_logs_detect_automation_account_create,
    detection.activity_logs_detect_automation_runbook_create_modify,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/Automation"
  })
}

detection "activity_logs_detect_automation_webhook_create" {
  title       = "Detect Automation Account Webhook Created"
  description = "Detects the creation of Azure Automation account webhook."
  severity    = "low"
  query       = query.activity_logs_detect_automation_webhook_create

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://www.ciraltos.com/webhooks-and-azure-automation-runbooks/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_runbook_delete" {
  title       = "Detect Automation Account Runbook Deleted"
  description = "Detects the deletion of Azure Automation account runbook."
  severity    = "low"
  query       = query.activity_logs_detect_automation_runbook_delete

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_account_create" {
  title       = "Detect Automation Account Created"
  description = "Detects the creation of Azure Automation account."
  severity    = "low"
  query       = query.activity_logs_detect_automation_account_create

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_automation_runbook_create_modify" {
  title       = "Detect Automation Runbook Created or Modified"
  description = "Detects the creation or modification of Azure Automation runbook."
  severity    = "low"
  query       = query.activity_logs_detect_automation_runbook_create_modify

  references = [
    "https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor",
    "https://github.com/hausec/PowerZure",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/",
  ]

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_automation_webhook_create" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Automation/automationAccounts/webhooks/action',
        'Microsoft.Automation/automationAccounts/webhooks/write'
      )
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_automation_runbook_delete" {
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

query "activity_logs_detect_automation_account_create" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Automation/automationAccounts/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_automation_runbook_create_modify" {
  sql = <<-EOQ
    select
     ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Automation/automationAccounts/runbooks/draft/write',
        'Microsoft.Automation/automationAccounts/runbooks/write',
        'Microsoft.Automation/automationAccounts/runbooks/publish/action',
      )
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
