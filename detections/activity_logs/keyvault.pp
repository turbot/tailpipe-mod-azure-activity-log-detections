locals {
  keyvault_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/KeyVault"
  })
}

benchmark "activity_logs_keyvault_detections" {
  title       = "Key Vault Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Key Vault activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_keyvault_vault_deletions,
    detection.activity_logs_detect_keyvault_vault_access_policy_updates,
    detection.activity_logs_detect_keyvault_secret_updates,
    detection.activity_logs_detect_keyvault_secret_deletions,
    detection.activity_logs_detect_keyvault_secret_restore_operations,
  ]

  tags = merge(local.keyvault_common_tags, {
    type = "Benchmark"
  })
}

# Detections

detection "activity_logs_detect_keyvault_vault_deletions" {
  title           = "Detect Key Vault Vault Deletions"
  description     = "Detect Azure Key Vault vaults to check for deletions, which may lead to data or service loss."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_keyvault_vault_deletions

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_keyvault_vault_access_policy_updates" {
  title           = "Detect Key Vault Vault Access Policy Updates"
  description     = "Detect Azure Key Vault vaults to check for access policy updates, which may impact security by changing permissions."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_keyvault_vault_access_policy_updates

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "activity_logs_detect_keyvault_secret_updates" {
  title           = "Detect Key Vault Secret Updates"
  description     = "Detect Azure Key Vault secrets to check for updates, which may indicate changes to critical configurations or data."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_keyvault_secret_updates

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0040:T1565.001"
  })
}

detection "activity_logs_detect_keyvault_secret_deletions" {
  title           = "Detect Key Vault Secret Deletions"
  description     = "Detect Azure Key Vault secrets to check for deletions, which could result in loss of sensitive data or disruption of services."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_keyvault_secret_deletions

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_keyvault_secret_restore_operations" {
  title           = "Detect Key Vault Secret Restore Operations"
  description     = "Detect Azure Key Vault secrets to check for restore operations, which may introduce outdated or unverified data."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.activity_logs_detect_keyvault_secret_restore_operations

  tags = merge(local.keyvault_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

# Queries

query "activity_logs_detect_keyvault_vault_deletions" {
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

query "activity_logs_detect_keyvault_vault_access_policy_updates" {
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

query "activity_logs_detect_keyvault_secret_updates" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/secrets/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secret_deletions" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/secrets/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secret_restore_operations" {
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