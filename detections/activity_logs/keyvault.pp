locals {
  activity_log_keyvault_detection_common_tags = merge(local.activity_log_detection_common_tags, {
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

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

# Detections

detection "activity_logs_detect_keyvault_vault_deletions" {
  title       = "Detect Key Vault Deletions"
  description = "Detect Azure Key Vault vaults to check for deletions, which may lead to data or service loss."
  severity    = "high"
  query       = query.activity_logs_detect_keyvault_vault_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_keyvault_vault_access_policy_updates" {
  title       = "Detect Key Vault Access Policy Updates"
  description = "Detect Azure Key Vault vaults to check for access policy updates, which may impact security by changing permissions."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_vault_access_policy_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "activity_logs_detect_keyvault_secret_updates" {
  title       = "Detect Key Vault Secret Updates"
  description = "Detect Azure Key Vault secrets to check for modifications, which may indicate changes to critical configurations or data."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_secret_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1565.001"
  })
}

detection "activity_logs_detect_keyvault_secret_deletions" {
  title       = "Detect Key Vault Secret Deletions"
  description = "Detect Azure Key Vault secrets to check for deletions, which could result in loss of sensitive data or disruption of services."
  severity    = "high"
  query       = query.activity_logs_detect_keyvault_secret_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_keyvault_secret_restore_operations" {
  title       = "Detect Key Vault Secret Restore Operations"
  description = "Detect Azure Key Vault secrets to check for restore operations, which may introduce outdated or unverified data."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_secret_restore_operations

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1537"
  })
}

# Queries

query "activity_logs_detect_keyvault_vault_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_vault_access_policy_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/accessPolicies/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secret_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/secrets/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secret_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/secrets/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secret_restore_operations" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.KeyVault/vaults/secrets/restore/action'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}