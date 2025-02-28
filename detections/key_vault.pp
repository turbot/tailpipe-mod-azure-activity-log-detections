locals {
  key_vault_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    folder  = "Key Vault"
    service = "Azure/KeyVault"
  })
}

benchmark "key_vault_detections" {
  title       = "Key Vault Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Key Vault activity logs."
  type        = "detection"
  children = [
    detection.key_vault_access_policy_created_or_updated,
    detection.key_vault_deleted,
  ]

  tags = merge(local.key_vault_common_tags, {
    type = "Benchmark"
  })
}

# Detections

detection "key_vault_deleted" {
  title           = "Key Vault Deleted"
  description     = "Detect when an Azure Key Vault was deleted, potentially leading to data or service loss and impacting the availability of critical secrets, keys, or certificates."
  documentation   = file("./detections/docs/key_vault_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.key_vault_deleted

  tags = merge(local.key_vault_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "key_vault_access_policy_created_or_updated" {
  title           = "Key Vault Access Policy Created or Updated"
  description     = "Detect when an Azure Key Vault access policy was created or updated, which may impact security by changing permissions and potentially allowing unauthorized access or privilege escalation."
  documentation   = file("./detections/docs/key_vault_access_policy_created_or_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.key_vault_access_policy_created_or_updated

  tags = merge(local.key_vault_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

# Queries

query "key_vault_deleted" {
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

  tags = local.key_vault_common_tags
}

query "key_vault_access_policy_created_or_updated" {
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

  tags = local.key_vault_common_tags
}
