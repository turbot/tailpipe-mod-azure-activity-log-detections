locals {
  keyvault_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/KeyVault"
  })
}

benchmark "keyvault_detections" {
  title       = "Key Vault Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Key Vault activity logs."
  type        = "detection"
  children = [
    detection.keyvault_deleted,
    detection.keyvault_access_policy_updated
  ]

  tags = merge(local.keyvault_common_tags, {
    type = "Benchmark"
  })
}

# Detections

detection "keyvault_deleted" {
  title           = "Key Vault Deleted"
  description     = "Detect when an Azure Key Vault was deleted, potentially leading to data or service loss and impacting the availability of critical secrets, keys, or certificates."
  documentation   = file("./detections/docs/keyvault_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.keyvault_deleted

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "keyvault_access_policy_updated" {
  title           = "Key Vault Access Policy Updated"
  description     = "Detect when an Azure Key Vault access policy is updated, which may impact security by changing permissions and potentially allowing unauthorized access or privilege escalation."
  documentation   = file("./detections/docs/keyvault_access_policy_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.keyvault_access_policy_updated

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

# Queries

query "keyvault_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "keyvault_access_policy_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/accessPolicies/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_keyvault_secret_restore_operations" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/secrets/restore/action'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}