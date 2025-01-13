locals {
  mitre_v151_ta0040_t1565_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1565"
  })
}

benchmark "mitre_v151_ta0040_t1565" {
  title         = "T1565 Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1565.md")
  children = [
    benchmark.mitre_v151_ta0040_t1565_001,
  ]

  tags = local.mitre_v151_ta0040_t1565_common_tags
}

benchmark "mitre_v151_ta0040_t1565_001" {
  title         = "T1565.001 Data Manipulation: Stored Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1565_001.md")
  children = [
    detection.activity_logs_detect_keyvault_secret_updates,
    detection.activity_logs_detect_diagnostic_setting_deletions,
  ]
}