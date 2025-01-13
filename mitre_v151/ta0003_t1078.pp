locals {
  mitre_v151_ta0003_t1078_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v151_ta0003_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003_t1078.md")
  children = [
    benchmark.mitre_v151_ta0003_t1078_001,
    benchmark.mitre_v151_ta0003_t1078_004,
  ]

  tags = local.mitre_v151_ta0003_t1078_common_tags
}

benchmark "mitre_v151_ta0003_t1078_001" {
  title         = "T1078.001 Valid Accounts: Default Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003_t1078_001.md")
  children = [
    detection.activity_logs_detect_event_hub_auth_rule_updations,
  ]
}

benchmark "mitre_v151_ta0003_t1078_004" {
  title         = "T1078.004 Valid Accounts: Cloud Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003_t1078_004.md")
  children = [
    detection.activity_logs_detect_authorization_role_assignment_updations,
    detection.activity_logs_detect_keyvault_secret_restore_operations,
    detection.activity_logs_detect_keyvault_vault_access_policy_updates,
    detection.activity_logs_detect_sql_role_assignment_changes,
    detection.activity_logs_detect_vm_role_assignment_changes,
  ]
}