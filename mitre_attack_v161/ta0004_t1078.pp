locals {
  mitre_attack_v161_ta0004_t1078_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_attack_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0004_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1078.md")
  children = [
  ]

  tags = local.mitre_attack_v161_ta0004_t1078_common_tags
}