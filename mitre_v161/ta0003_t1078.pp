locals {
  mitre_v161_ta0003_t1078_common_tags = merge(local.mitre_v161_ta0003_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v161_ta0003_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1078.md")
  children = [
    benchmark.mitre_v161_ta0003_t1078_001,
    benchmark.mitre_v161_ta0003_t1078_004,
  ]

  tags = local.mitre_v161_ta0003_t1078_common_tags
}

benchmark "mitre_v161_ta0003_t1078_001" {
  title         = "T1078.001 Valid Accounts: Default Accounts"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1078_001.md")
  children = [
    detection.event_hub_namespace_rule_authorized,
  ]
}

benchmark "mitre_v161_ta0003_t1078_004" {
  title         = "T1078.004 Valid Accounts: Cloud Accounts"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1078_004.md")
  children = [
    detection.iam_role_assignment_updated,
    detection.keyvault_access_policy_updated,
    detection.sql_server_role_assignment_updated,
    detection.compute_vm_role_assignment_updated,
  ]
}