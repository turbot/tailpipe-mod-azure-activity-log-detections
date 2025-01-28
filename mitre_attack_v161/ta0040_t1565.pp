locals {
  mitre_attack_v161_ta0040_t1565_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1565"
  })
}

benchmark "mitre_attack_v161_ta0040_t1565" {
  title         = "T1565 Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1565.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1565_001,
  ]

  tags = local.mitre_attack_v161_ta0040_t1565_common_tags
}

benchmark "mitre_attack_v161_ta0040_t1565_001" {
  title         = "T1565.001 Data Manipulation: Stored Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1565_001.md")
  children = [
    detection.diagnostic_setting_deleted,
  ]
}