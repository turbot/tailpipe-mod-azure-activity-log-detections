locals {
  storage_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    folder  = "Storage"
    service = "Azure/Storage"
  })
}

benchmark "storage_detections" {
  title       = "Storage Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Storage activity logs."
  type        = "detection"
  children = [
    detection.storage_account_deleted,
    detection.storage_account_key_regenerated,
    detection.storage_account_lifecycle_policy_updated,
  ]

  tags = merge(local.storage_common_tags, {
    type = "Benchmark"
  })
}

detection "storage_account_key_regenerated" {
  title           = "Storage Account Key Regenerated"
  description     = "Detect when Azure Storage Account key was regenerated, which may impact security by enabling unauthorized access to the account or disrupting dependent applications using the old keys."
  documentation   = file("./detections/docs/storage_account_key_regenerated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.storage_account_key_regenerated

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0006:T1552.001"
  })
}

detection "storage_account_lifecycle_policy_updated" {
  title           = "Storage Account Lifecycle Policy Updated"
  description     = "Detect when Azure Storage Account lifecycle policies are updated, potentially leading to data destruction by modifying rules that trigger unintended deletions or move data to less secure storage tiers."
  documentation   = file("./detections/docs/storage_account_lifecycle_policy_updated.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.storage_account_lifecycle_policy_updated

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0040:T1485.001"
  })
}

detection "storage_account_deleted" {
  title           = "Storage Account Deleted"
  description     = "Detect when an Azure Storage Account is deleted, potentially disrupting storage management, causing data loss, and impacting dependent applications or workflows."
  documentation   = file("./detections/docs/storage_account_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.storage_account_deleted

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "storage_account_deleted" {
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

  tags = local.storage_common_tags
}

query "storage_account_lifecycle_policy_updated" {
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

  tags = local.storage_common_tags
}

query "storage_account_key_regenerated" {
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

  tags = local.storage_common_tags
}
