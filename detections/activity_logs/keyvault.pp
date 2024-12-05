detection_benchmark "activity_logs_keyvault_detections" {
  title = "Activity Log Key Vault Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Key Vault activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_keyvault_secrets_modify_delete,
    detection.activity_logs_detect_keyvaults_modify_delete,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/KeyVault"
  })
}

detection "activity_logs_detect_keyvaults_modify_delete" {
  title       = "Detect Key Vaults Modified or Deleted"
  description = "Detects when a key vault is modified or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvaults_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_keyvault_secrets_modify_delete" {
  title       = "Detect Key Vault Secrets Modified or Deleted"
  description = "Detects when secrets are modified or deleted in Azure."
  severity    = "medium"
  query       = query.activity_logs_detect_keyvault_secrets_modify_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/security#microsoftkeyvault",
  ]

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_keyvaults_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.KeyVault/vaults/write',
        'Microsoft.KeyVault/vaults/delete',
        'Microsoft.KeyVault/vaults/accessPolicies/write',
        'Microsoft.KeyVault/vaults/deploy/action'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_keyvault_secrets_modify_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.KeyVault/vaults/secrets/write',
        'Microsoft.KeyVault/vaults/secrets/delete',
        'Microsoft.KeyVault/vaults/secrets/backup/action',
        'Microsoft.KeyVault/vaults/secrets/purge/action',
        'Microsoft.KeyVault/vaults/secrets/update/action',
        'Microsoft.KeyVault/vaults/secrets/recover/action',
        'Microsoft.KeyVault/vaults/secrets/restore/action',
        'Microsoft.KeyVault/vaults/secrets/setSecret/action'
      )
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}