locals {
  storage_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/Storage"
  })
}

benchmark "activity_logs_storage_detections" {
  title       = "Storage Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Storage activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_storage_account_keys_regenerated,
    detection.activity_logs_detect_lifecycle_policy_updates,
    detection.activity_logs_detect_storage_account_deletions,
  ]

  tags = merge(local.storage_common_tags, {
    type = "Benchmark"
  })
}

detection "activity_logs_detect_storage_account_keys_regenerated" {
  title           = "Detect Storage Account Keys Regenerated"
  description     = "Detects the regeneration of Storage account keys, providing visibility into significant changes that may impact security."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_storage_account_keys_regenerated

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0006:T1552.001"
  })
}

detection "activity_logs_detect_lifecycle_policy_updates" {
  title           = "Detect Azure Storage Lifecycle Policy Updates"
  description     = "Detect changes to Azure Storage lifecycle policies, which could result in data destruction by setting rules that trigger unintended deletions."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_lifecycle_policy_updates

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0040:T1485.001"
  })
}

detection "activity_logs_detect_storage_account_deletions" {
  title           = "Detect Storage Account Deletions"
  description     = "Detect the deletions of Azure Storage accounts, providing visibility into significant changes that may impact storage management."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_storage_account_deletions

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "activity_logs_detect_storage_account_deletions" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_lifecycle_policy_updates" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/managementPolicies/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_storage_account_keys_regenerated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/regenerateKey/action'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
