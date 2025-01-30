locals {
  mitre_attack_v161_ta0006_t1552_common_tags = merge(local.mitre_attack_v161_ta0006_common_tags, {
    mitre_attack_technique_id = "T1552"
  })
}

benchmark "mitre_attack_v161_ta0006_t1552" {
  title         = "T1552 Unsecured Credentials"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1552.md")
  children = [
    benchmark.mitre_attack_v161_ta0006_t1552_001,
  ]

  tags = local.mitre_attack_v161_ta0006_t1552_common_tags
}

benchmark "mitre_attack_v161_ta0006_t1552_001" {
  title         = "T1552.001 Unsecured Credentials: Credentials In Files"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1552_001.md")
  children = [
    detection.storage_account_key_regenerated,
  ]

  tags = merge(local.mitre_attack_v161_ta0006_t1552_common_tags, {
    mitre_attack_technique_id = "T1552.001"
  })
}

