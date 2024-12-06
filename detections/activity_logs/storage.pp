benchmark "activity_logs_storage_detections" {
  title = "Activity Log Storage Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Storage activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_storage_account_key_regenerated,
    detection.activity_logs_detect_storage_blob_container_access_modify,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/Storage"
  })
}

detection "activity_logs_detect_storage_account_key_regenerated" {
  title       = "Detect Storage accounts key regenerated"
  description = "Detects the regeneration of Storage accounts key."
  severity    = "low"
  query       = query.activity_logs_detect_storage_account_key_regenerated

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_storage_blob_container_access_modify" {
  title       = "Detect Storage Blob Container Access Modified"
  description = "Detects the modification of Azure Storage Blob Container access."
  severity    = "low"
  query       = query.activity_logs_detect_storage_blob_container_access_modify

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_storage_account_key_regenerated" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/regenerateKey/action'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_storage_blob_container_access_modify" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Storage/storageAccounts/blobServices/containers/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
